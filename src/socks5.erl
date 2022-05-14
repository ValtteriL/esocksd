-module(socks5).
-include("socks5.hrl").
-include("common.hrl").

-export([handshake/2, authenticate/2, negotiate/2, udp_associate_relay/2]).

% SOCKS5 + SOCKS5H related functions
% followed documents: 
% - https://datatracker.ietf.org/doc/html/rfc1928
% - https://datatracker.ietf.org/doc/html/rfc1929

-spec handshake(binary(), state()) -> tuple().
handshake(Msg, State) ->
    <<5, NMETHODS, METHODS/binary>> = Msg,

    DbgMsg = io_lib:format("Received SOCKS5 handshake message with ~B methods", [NMETHODS]),
    socks_worker:log_debug(State#state.workerId, DbgMsg),

    ListMETHODS = binary:bin_to_list(METHODS),

    UserPassProposed = lists:member(?M_USERPASS, ListMETHODS),
    NoAuthProposed = lists:member(?M_NOAUTH, ListMETHODS),

    % if authentication required, check that client proposes it
    case {config:auth_required(), UserPassProposed, NoAuthProposed } of
        {true, true, _} ->
            % choose M_USERPASS method, and move to authentication stage
            socks_worker:log_debug(State#state.workerId, "Choosing userpass"),
            gen_tcp:send(State#state.socket, <<5, ?M_USERPASS>>),
            {noreply, State#state{stage=#stage.authenticate}};
        {false, _, true} ->
            % choose M_NOAUTH method, and move to next stage
            socks_worker:log_debug(State#state.workerId, "Choosing noauth"),
            gen_tcp:send(State#state.socket, <<5, ?M_NOAUTH>>),
            {noreply, State#state{stage=#stage.request}};
        _ -> 
            % reply no, end connection, and terminate worker
            socks_worker:log_info(State#state.workerId, "No supported auth method found"),
            gen_tcp:send(State#state.socket, <<5, ?M_NOTAVAILABLE>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end.

-spec authenticate(binary(), state()) -> tuple().
authenticate(Msg, State) ->
    % +----+------+----------+------+----------+
    % |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    % +----+------+----------+------+----------+
    % | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    % +----+------+----------+------+----------+
    <<1, ULEN, UNAME:ULEN/binary, PLEN, PASSWD:PLEN/binary>> = Msg,

    Username = binary_to_list(UNAME),
    Password = binary_to_list(PASSWD),

    % +----+--------+
    % |VER | STATUS |
    % +----+--------+
    % | 1  |   1    |
    %+----+--------+
    case config:auth_credentials_correct(Username, Password) of
        true ->
            % valid creds: continue to request state
            StatusMsg = io_lib:format("Userpass authentication successful with username \"~s\"", [Username]),
            socks_worker:log_notice(State#state.workerId, StatusMsg),
            gen_tcp:send(State#state.socket, <<1, ?USERPASS_STATUS_SUCCESS>>),
            {noreply, State#state{stage=#stage.request}};
        _ ->
            % invalid creds: end connection and terminate worker
            socks_worker:log_warning(State#state.workerId, "Userpass authentication failed (invalid credentials)"),
            gen_tcp:send(State#state.socket, <<1, ?USERPASS_STATUS_FAILURE>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end.

-spec negotiate(binary(), state()) -> tuple().
negotiate(Msg, State) ->
    <<_VER, CMD, ?RSV, ATYP, Rest/binary>> = Msg,

    {DST_ADDR, DST_PORT} = case ATYP of
        ?ATYP_IPV4 ->
            <<DST:4/binary, T/binary>> = Rest,
            {helpers:bytes_to_addr(DST), binary:decode_unsigned(T)};
        ?ATYP_DOMAINNAME ->
            <<DOMAIN_LEN, DST_HOST:DOMAIN_LEN/binary, T/binary>> = Rest,

            NoticeMsg = io_lib:format("Domain used as DST (~s)", [DST_HOST]),
            socks_worker:log_notice(State#state.workerId, NoticeMsg),

            DST = helpers:resolve(binary_to_list(DST_HOST)),
            {DST, binary:decode_unsigned(T)};
        ?ATYP_IPV6 ->
            <<DST:16/binary, T/binary>> = Rest,
            {helpers:bytes_to_addr(DST), binary:decode_unsigned(T)};
        _ ->
            socks_worker:log_warning(State#state.workerId, "Unsupported ATYP reveived"),
            gen_tcp:send(State#state.socket, <<5, ?REP_ATYPE_NOT_SUPPORTED, ?RSV, ?REP_PADDING/binary>>),
            gen_tcp:shutdown(State#state.socket, write)
    end,

    DbgMsg = io_lib:format("Received SOCKS request CMD: ~B, ATYP: ~B, DST_ADDR: ~s, DST_PORT: ~B", [CMD, ATYP, inet:ntoa(DST_ADDR), DST_PORT]),
    socks_worker:log_debug(State#state.workerId, DbgMsg),

    Command = case CMD of
        ?CMD_CONNECT ->
            socks_worker:log_debug(State#state.workerId, "CONNECT request received"),
            connect;
        ?CMD_BIND ->
            socks_worker:log_debug(State#state.workerId, "BIND request received"),
            bind;
        ?CMD_UDP_ASSOCIATE ->
            socks_worker:log_debug(State#state.workerId, "UDP ASSOCIATE request received"),
            udp_associate
    end,

    case {Command, config:command_allowed(Command)} of
        {bind, true} -> bind(State);
        {connect, true} ->
            case config:address_allowed(DST_ADDR) of
                true -> connect(DST_ADDR, DST_PORT, State);
                false -> close_network_disallowed(State)
            end; 
        {udp_associate, true} ->

            AddrUnknown = case {DST_ADDR,  DST_PORT} of
                {{0,0,0,0}, 0} -> true;
                {{0,0,0,0,0,0,0,0}, 0} -> true;
                _-> false
            end,

            % block if client intends to use disallowed IP
            % as the source

            case config:address_allowed(DST_ADDR) or AddrUnknown of
                true -> udp_associate(DST_ADDR, DST_PORT, State);
                false -> close_network_disallowed(State)
            end; 
        {_, false} ->
            socks_worker:log_warning(State#state.workerId, "Command not allowed"),
            gen_tcp:send(State#state.socket, <<5, ?REP_CMD_NOT_SUPPORTED, ?RSV, ?REP_PADDING/binary>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end.


% handle CONNECT command
% connects to a remote host
% stores the socket to connectSocket in state
% then relay traffic between socket and connectSocket
connect(DST_ADDR, DST_PORT, State) ->

    DbgMsg = io_lib:format("Connecting to ~s:~B", [inet:ntoa(DST_ADDR), DST_PORT]),
    socks_worker:log_debug(State#state.workerId, DbgMsg),

    case  gen_tcp:connect(DST_ADDR, DST_PORT, [], 5000) of
        {ok, Socket} ->

            NoticeMsg = io_lib:format("Connected to ~s:~B", [inet:ntoa(DST_ADDR), DST_PORT]),
            socks_worker:log_notice(State#state.workerId, NoticeMsg),

            {ok, {IfAddr, Port}} = inet:sockname(Socket),
            PortBytes = helpers:integer_to_2byte_binary(Port),
            IfAddrBytes = helpers:addr_to_bytes(IfAddr),
            
            % communicate the bound hostname and port
            gen_tcp:send(State#state.socket, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes/binary, PortBytes/binary>>),

            % convert received data to Erlang messages
            ok = inet:setopts(Socket, [{active, once}]),
            
            {noreply, State#state{stage=#stage.connect, connectSocket=Socket}};
        {error, Reason} ->

            ErrMsg = io_lib:format("Failed to connect to remote host: ~p", [Reason]),
            socks_worker:log_warning(State#state.workerId, ErrMsg),

            case Reason of
                enetunreach -> gen_tcp:send(State#state.socket, <<5, ?REP_NETWORK_UNREACHABLE, ?RSV, ?REP_PADDING/binary>>);
                ehostunreach -> gen_tcp:send(State#state.socket, <<5, ?REP_HOST_UNREACHABLE, ?RSV, ?REP_PADDING/binary>>);
                econnrefused -> gen_tcp:send(State#state.socket, <<5, ?REP_CONN_REFUSED, ?RSV, ?REP_PADDING/binary>>);
                _ -> gen_tcp:send(State#state.socket, <<5, ?REP_GEN_FAILURE, ?RSV, ?REP_PADDING/binary>>)
            end,
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end.

% handle BIND command
% starts listening for TCP connections
% stores the listening socket to connectSocket
% once connection received relay traffic between socket and connectSocket
bind(State) ->
    % bind socket on random tcp port
    {ok, ListenSocket} = gen_tcp:listen(0, []),
    {ok, {IfAddr, Port}} = inet:sockname(ListenSocket),

    DbgMsg = io_lib:format("Listening for connections on port ~B...", [Port]),
    socks_worker:log_info(State#state.workerId, DbgMsg),

    PortBytes = helpers:integer_to_2byte_binary(Port),
    IfAddrBytes = helpers:addr_to_bytes(IfAddr),

    % communicate the bound hostname and port
    gen_tcp:send(State#state.socket, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes/binary, PortBytes/binary>>),

    % wait for connection to the socket
    case gen_tcp:accept(ListenSocket, 60*1000*2) of
        {ok, Socket} ->

            % convert received data to Erlang messages
            ok = inet:setopts(Socket, [{active, once}]),

            % get peer info
            {ok,{RemoteAddr,RemotePort}} = inet:peername(Socket),
            RemoteAddrBytes = helpers:addr_to_bytes(RemoteAddr),
            RemotePortBytes = helpers:integer_to_2byte_binary(RemotePort),

            StatusMsg = io_lib:format("Connection received to BIND from ~s:~B", [inet:ntoa(RemoteAddr), RemotePort]),
            socks_worker:log_notice(State#state.workerId, StatusMsg),

            case config:address_allowed(RemoteAddr) of
                true ->
                    % communicate the received connection and peer details
                    gen_tcp:send(State#state.socket, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, RemoteAddrBytes/binary, RemotePortBytes/binary>>),
                    {noreply, State#state{stage=#stage.connect, connectSocket=Socket}};
                false -> 
                    % received connection from disallowed host - communicate error
                    
                    WarnMsg = io_lib:format("Accepted connection from disallowed host (~s:~B)", [inet:ntoa(RemoteAddr), RemotePort]),
                    socks_worker:log_warning(State#state.workerId, WarnMsg),

                    gen_tcp:send(State#state.socket, <<5, ?REP_GEN_FAILURE, ?RSV, ?REP_PADDING/binary>>),
                    gen_tcp:shutdown(State#state.socket, write),
                    gen_tcp:close(ListenSocket),
                    gen_tcp:close(Socket),
                    {stop, normal, State}
            end;
        {error, _} ->

            socks_worker:log_warning(State#state.workerId, "Error accepting connection"),

            % communicate error
            gen_tcp:send(State#state.socket, <<5, ?REP_GEN_FAILURE, ?RSV, ?REP_PADDING/binary>>),
            gen_tcp:shutdown(State#state.socket, write),
            gen_tcp:close(ListenSocket),
            {stop, normal, State}
    end.


% handle UDP ASSOCIATE command
% starts listening for UDP connections
% stores the socket somewhere
% when data received on UDP, it is relayed based on the header
% when destination host replies, header is prepended and datagram is sent to the client
udp_associate(DST_ADDR, DST_PORT, State) ->
    % bind socket on random udp port on both ipv4 and ipv6
    {ok, ListenSocketIpv4} = gen_udp:open(0, [inet, binary, {active, once}]),
    {ok, Port} = inet:port(ListenSocketIpv4),
    {ok, ListenSocketIpv6} = gen_udp:open(Port, [inet6, binary, {active, once}]),
    
    {ok, {IfAddr, Port}} = inet:sockname(ListenSocketIpv4),

    StatusMsg = io_lib:format("Listening for UDP connections on ~s, port ~B", [inet:ntoa(IfAddr), Port]),
    socks_worker:log_info(State#state.workerId, StatusMsg),

    PortBytes = helpers:integer_to_2byte_binary(Port),
    IfAddrBytes = helpers:addr_to_bytes(IfAddr),

    % communicate the bound hostname and port
    gen_tcp:send(State#state.socket, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes/binary, PortBytes/binary>>),

    UDPClient = case {DST_ADDR, DST_PORT} of
        {IP, 0} when (IP == {0,0,0,0}) or (IP == {0,0,0,0,0,0,0,0}) ->
            % client does not know which IP:Port it will use - use the client IP 
            {ok,{RemoteAddr,_RemotePort}} = inet:peername(State#state.socket),
            RemoteAddr;
        _ ->
            % client uses this IP to send UDP traffic
            DST_ADDR
    end,

    % store the ListenSocket and used IP
    {noreply, State#state{stage=#stage.udp_associate, connectSocket=ListenSocketIpv4, connectSocketIpv6=ListenSocketIpv6, udpClientIP=UDPClient}}.


% relay data in UDP ASSOCIATE
% UDP port receives data with header
% UDP port receives data without header
-spec udp_associate_relay(tuple(), state()) -> tuple().
udp_associate_relay({udp, Socket, IP, InPortNo, Msg}, State) ->

    ok = inet:setopts(Socket, [{active, once}]),
    socks_worker:log_debug(State#state.workerId, "Passing UDP data"),

    % expect encapsulated traffic from client
    case ((IP == State#state.udpClientIP) and ((InPortNo == State#state.udpClientPort) or (State#state.udpClientPort==undefined))) of
        true ->
            socks_worker:log_debug(State#state.workerId, "Client sends UDP traffic to DST"),
            % client sent this (store the Port)
            <<?RSV, ?RSV, ?UDP_FRAG,  ATYP, Rest/binary>> = Msg,
            {DST_ADDR, DST_PORT, Data} = case ATYP of
                ?ATYP_IPV4 ->
                    <<DST:4/binary, T:2/binary, Datagram/binary>> = Rest,
                    DstAddr = helpers:bytes_to_addr(DST),
                    InfoMsg = io_lib:format("Client sends UDP traffic to ~s:~B", [inet:ntoa(DstAddr), binary:decode_unsigned(T)]),
                    {DstAddr, T, Datagram};
                ?ATYP_DOMAINNAME ->
                    <<DOMAIN_LEN, T1/binary>> = Rest,
                    <<DST_HOST:DOMAIN_LEN/binary, T:2/binary, Datagram/binary>> = T1,
                    DST = binary_to_list(DST_HOST),
                    InfoMsg = io_lib:format("Client sends UDP traffic to ~s:~B", [DST,binary:decode_unsigned(T)]),
                    {helpers:resolve(DST), T, Datagram};
                ?ATYP_IPV6 ->
                    <<DST:16/binary, T:2/binary, Datagram/binary>> = Rest,
                    DstAddr = helpers:bytes_to_addr(DST),
                    InfoMsg = io_lib:format("Client sends UDP traffic to ~s:~B", [inet:ntoa(DstAddr), binary:decode_unsigned(T)]),
                    {DstAddr, T, Datagram}
            end,

            socks_worker:log_info(State#state.workerId, InfoMsg),

            % relay Data to the destination if address allowed
            % otherwise drop
            AddrAllowed = config:address_allowed(DST_ADDR),
            case {AddrAllowed, ATYP} of
                {true, ?ATYP_IPV6 } -> 
                    ok = gen_udp:send(State#state.connectSocketIpv6, DST_ADDR, binary:decode_unsigned(DST_PORT), Data);
                {true, _} -> 
                    ok = gen_udp:send(State#state.connectSocket, DST_ADDR, binary:decode_unsigned(DST_PORT), Data);
                {false, _} -> 
                    socks_worker:log_warning(State#state.workerId, "Dropping traffic destined to disallowed address")
            end,

            {noreply, State#state{udpClientPort=InPortNo}};
        _->

            socks_worker:log_debug(State#state.workerId, "DST sends UDP traffic to client"),
            
            % this is reply from the destination host
            
            case config:address_allowed(IP) of
                true -> 
                    % prepend header and send to client

                    InfoMsg = io_lib:format("DST (~s:~B) sends UDP traffic to client", [inet:ntoa(IP), InPortNo]),
                    socks_worker:log_info(State#state.workerId, InfoMsg),
            
                    RemoteAddrBytes = helpers:addr_to_bytes(IP),
                    RemotePortBytes = helpers:integer_to_2byte_binary(InPortNo),

                    % get type of address
                    ATYP = helpers:bytes_to_atyp(RemoteAddrBytes),

                    Data = <<?UDP_RSV/binary, ?UDP_FRAG, ATYP, RemoteAddrBytes/binary, RemotePortBytes/binary, Msg/binary>>,

                    % relay Data to client using suitable socket
                    % if the destination IP is itself allowed
                    case tuple_size(State#state.udpClientIP) of
                        4 -> 
                            ok = gen_udp:send(State#state.connectSocket, State#state.udpClientIP, State#state.udpClientPort, Data);
                        _ ->
                            ok = gen_udp:send(State#state.connectSocketIpv6, State#state.udpClientIP, State#state.udpClientPort, Data)
                    end;
                false -> socks_worker:log_warning(State#state.workerId, "Dropping traffic from disallowed address")
            end,

            {noreply, State}
    end.


%% helpers

% close connection cleanly
close_network_disallowed(State) ->
    socks_worker:log_warning(State#state.workerId, "Network not allowed"),
    gen_tcp:send(State#state.socket, <<5, ?REP_CONNECTION_NOT_ALLOWED, ?RSV, ?REP_PADDING/binary>>),
    gen_tcp:shutdown(State#state.socket, write),
    gen_tcp:close(State#state.socket),
    {stop, normal, State}.
