-module(socks_worker).
-behaviour(gen_server).
-include("socks5.hrl").

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).

-record(stage,{
    handshake, % nothing exchanged yet - do handshake
    authenticate, % handshake done and auth required - do authentication
    request, % handshake (and auth) done - receive SOCKS request
    connect, % CONNECT or BIND in place and connected - relay TCP traffic
    udp_associate % UDP ASSOCIATE in place - relay UDP traffic
}).
-record(state, {socket, connectSocket, connectSocketIpv6, stage = #stage.handshake, udpClientIP, udpClientPort}).

% RFCs https://www.synopsys.com/software-integrity/security-testing/fuzz-testing/defensics/protocols/socks-client.html
% SOCKS5
% SOCKS5h 

start_link(Socket) ->
    gen_server:start_link(?MODULE, [Socket], []).

init([Socket]) ->
    gen_server:cast(self(), accept),
    {ok, #state{socket=Socket}}.

% handle start message from self
handle_cast(accept, State) ->

    % accept new connection
    {ok, AcceptSocket} = gen_tcp:accept(State#state.socket),
    io:format("Worker: Accepted connection!~n", []),

    esocksd_sup:start_socket(), % start a new listener to replace this one
    {noreply, #state{socket=AcceptSocket }};

handle_cast(_, State) ->
    {noreply, State}.


% handle tcp traffic
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.handshake}) ->

    ok = inet:setopts(Socket, [{active, once}]),
    io:format("Worker: NEGOTIATION~n", []),

    <<VER, NMETHODS, METHODS/binary>> = Msg,
    io:format("Worker: SOCKS version: ~B, NMETHODS: ~B~n", [VER, NMETHODS]),

    ListMETHODS = binary:bin_to_list(METHODS),

    % check version and proposed auth method
    case {lists:member(VER, ?SUPPORTED_VERSIONS), lists:member(?M_NOAUTH, ListMETHODS)}  of
        {true, true} ->
            % choose M_NOAUTH method, and move to next stage
            io:fwrite("Worker: Supported SOCKS version and method found~n"),
            gen_tcp:send(State#state.socket, <<VER, ?M_NOAUTH>>),
            {noreply, State#state{stage=#stage.request}};
        {false, _} ->
            % reply no, end connection, and terminate worker
            io:fwrite("Worker: Unsupported SOCKS version...~n"),
            gen_tcp:send(State#state.socket, <<5, ?M_NOTAVAILABLE>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State};
        _ -> 
            % reply no, end connection, and terminate worker
            io:fwrite("Worker: Unsupported auth method proposed...~n"),
            gen_tcp:send(State#state.socket, <<VER, ?M_NOTAVAILABLE>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end;
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.request}) ->

    ok = inet:setopts(Socket, [{active, once}]),
    io:format("Worker: REQUEST~n", []),

    <<_VER, CMD, ?RSV, ATYP, Rest/binary>> = Msg,

    {DST_ADDR, DST_PORT} = case ATYP of
        ?ATYP_IPV4 ->
            <<DST:4/binary, T/binary>> = Rest,
            {bytes_to_addr(DST), T};
        ?ATYP_DOMAINNAME ->
            <<DOMAIN_LEN, T1/binary>> = Rest,
            <<DST_HOST:DOMAIN_LEN/binary, T/binary>> = T1,
            DST = binary_to_list(DST_HOST),
            {DST, T};
        ?ATYP_IPV6 ->
            <<DST:16/binary, T/binary>> = Rest,
            {bytes_to_addr(DST), T};
        _ ->
            io:fwrite("Worker: Unsupported ATYP received~n"),
            gen_tcp:send(State#state.socket, <<5, ?REP_ATYPE_NOT_SUPPORTED, ?RSV, ?REP_PADDING/binary>>),
            gen_tcp:shutdown(State#state.socket, write)
    end,

    io:format("Worker: CMD: ~B, ATYP: ~B, DST_ADDR: ~p, DST_PORT: ~B~n", [CMD, ATYP, DST_ADDR, binary:decode_unsigned(DST_PORT)]),

    case CMD of
        ?CMD_CONNECT ->
            io:fwrite("Worker: CONNECT request received~n"),
            connect(DST_ADDR, binary:decode_unsigned(DST_PORT), State);
        ?CMD_BIND ->
            io:fwrite("Worker: BIND request received~n"),
            bind(State);
        ?CMD_UDP_ASSOCIATE ->
            io:fwrite("Worker: UDP ASSOCIATE request received~n"),
            udp_associate(DST_ADDR, binary:decode_unsigned(DST_PORT), State);
        _->
            io:fwrite("Worker: Unsupported CMD received~n"),
            gen_tcp:send(State#state.socket, <<5, ?REP_CMD_NOT_SUPPORTED, ?RSV, ?REP_PADDING/binary>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end;
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.connect, socket=Socket}) ->
    ok = inet:setopts(Socket, [{active, once}]),
    io:format("Worker: passing TCP data from client to destination~n", []),
    gen_tcp:send(State#state.connectSocket, Msg),
    {noreply, State};
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.connect, connectSocket=Socket}) ->
    ok = inet:setopts(Socket, [{active, once}]),
    io:format("Worker: passing TCP data from destination to client~n", []),
    gen_tcp:send(State#state.socket, Msg),
    {noreply, State};
handle_info({tcp_closed, _Socket}, State) -> {stop, normal, State};
handle_info({tcp_error, _Socket, _}, State) -> {stop, normal, State};

% UDP port receives data with header
% UDP port receives data without header
handle_info({udp, Socket, IP, InPortNo, Msg}, State=#state{stage=#stage.udp_associate}) ->

    ok = inet:setopts(Socket, [{active, once}]),
    io:format("Worker: passing UDP data from client to destination~n", []),

    logger:critical("IP = ~p (state is ~p), InPortNo = ~p (state is ~p)", [IP, State#state.udpClientIP, InPortNo, State#state.udpClientPort]),

    % expect encapsulated traffic from client
    case ((IP == State#state.udpClientIP) and ((InPortNo == State#state.udpClientPort) or (State#state.udpClientPort==undefined))) of
        true ->
            logger:critical("CLIENT SENDS UDP TRAFFIC TO DST"),
            % client sent this (store the Port)
            <<?RSV, ?RSV, ?UDP_FRAG,  ATYP, Rest/binary>> = Msg,
            {DST_ADDR, DST_PORT, Data} = case ATYP of
                ?ATYP_IPV4 ->
                    <<DST:4/binary, T:2/binary, Datagram/binary>> = Rest,
                    {bytes_to_addr(DST), T, Datagram};
                ?ATYP_DOMAINNAME ->
                    <<DOMAIN_LEN, T1/binary>> = Rest,
                    <<DST_HOST:DOMAIN_LEN/binary, T:2/binary, Datagram/binary>> = T1,
                    DST = binary_to_list(DST_HOST),
                    {DST, T, Datagram};
                ?ATYP_IPV6 ->
                    <<DST:16/binary, T:2/binary, Datagram/binary>> = Rest,
                    {bytes_to_addr(DST), T, Datagram}
            end,

            % relay Data to the destination
            case ATYP of
                ?ATYP_IPV6 ->
                    ok = gen_udp:send(State#state.connectSocketIpv6, DST_ADDR, binary:decode_unsigned(DST_PORT), Data);
                _ ->
                    ok = gen_udp:send(State#state.connectSocket, DST_ADDR, binary:decode_unsigned(DST_PORT), Data)
            end,

            {noreply, State#state{udpClientPort=InPortNo}};
        _->

            logger:critical("DST SENDS UDP TRAFFIC TO CLIENT"),
            % this is reply from the destination host
            % prepend header and send to client
            
            RemoteAddrBytes = addr_to_bytes(IP),
            RemotePortBytes = integer_to_2byte_binary(InPortNo),

            % get type of address
            ATYP = bytes_to_atyp(RemoteAddrBytes),

            Data = <<?UDP_RSV/binary, ?UDP_FRAG, ATYP, RemoteAddrBytes/binary, RemotePortBytes/binary, Msg/binary>>,

            % send Data to client using suitable socket
            case tuple_size(State#state.udpClientIP) of
                4 -> 
                    ok = gen_udp:send(State#state.connectSocket, State#state.udpClientIP, State#state.udpClientPort, Data);
                _ ->
                    ok = gen_udp:send(State#state.connectSocketIpv6, State#state.udpClientIP, State#state.udpClientPort, Data)
            end,
            
            {noreply, State}
    end;


handle_info(E, State) ->
    io:fwrite("unexpected: ~p~n", [E]),
    logger:critical("UNEXPECTED: ~p", [E]),
    {noreply, State}.

handle_call(_E, _From, State) -> {noreply, State}.
terminate(_Reason, _Tab) -> ok.
code_change(_OldVersion, Tab, _Extra) -> {ok, Tab}.


%%% helpers



% handle CONNECT command
% connects to a remote host
% stores the socket to connectSocket in state
% then relay traffic between socket and connectSocket
connect(DST_ADDR, DST_PORT, State) ->
    case  gen_tcp:connect(DST_ADDR, DST_PORT, [], 5000) of
        {ok, Socket} ->
            io:fwrite("Worker: Connected!~n"),

            {ok, {IfAddr, Port}} = inet:sockname(Socket),
            PortBytes = integer_to_2byte_binary(Port),
            IfAddrBytes = addr_to_bytes(IfAddr),
            
            % communicate the bound hostname and port
            gen_tcp:send(State#state.socket, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes/binary, PortBytes/binary>>),

            % convert received data to Erlang messages
            ok = inet:setopts(Socket, [{active, once}]),
            
            {noreply, State#state{stage=#stage.connect, connectSocket=Socket}};
        {error, Reason} ->
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

    io:fwrite("Worker: Listening for connections on port ~B...~n", [Port]),

    PortBytes = integer_to_2byte_binary(Port),
    IfAddrBytes = addr_to_bytes(IfAddr),

    % communicate the bound hostname and port
    gen_tcp:send(State#state.socket, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes/binary, PortBytes/binary>>),

    % wait for connection to the socket
    case gen_tcp:accept(ListenSocket, 60*1000*1) of
        {ok, Socket} ->

            io:fwrite("Worker: Connection accepted~n", []),

            % convert received data to Erlang messages
            ok = inet:setopts(Socket, [{active, once}]),

            % get peer info
            {ok,{RemoteAddr,RemotePort}} = inet:peername(Socket),
            RemoteAddrBytes = addr_to_bytes(RemoteAddr),
            RemotePortBytes = integer_to_2byte_binary(RemotePort),

            io:fwrite("Worker: Connection received from ~p:~B!~n", [RemoteAddr, RemotePort]),

            % communicate the received connection and peer details
            gen_tcp:send(State#state.socket, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, RemoteAddrBytes/binary, RemotePortBytes/binary>>),
            {noreply, State#state{stage=#stage.connect, connectSocket=Socket}};
        {error, _} ->

            io:fwrite("Worker: Error accepting connection~n", []),

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

    io:fwrite("Worker: Listening for UDP connections on ~p, port ~B...~n", [IfAddr,Port]),

    PortBytes = integer_to_2byte_binary(Port),
    IfAddrBytes = addr_to_bytes(IfAddr),

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


% convert bytes into tuple representation of IP address (tuple)
bytes_to_addr(Bytes) ->
    case byte_size(Bytes) of
        4 ->
            A = binary:bin_to_list(Bytes),
            list_to_tuple(A);
        16 ->
            bytes_to_ipv6_addr(Bytes)
    end.

addr_to_bytes(Addr) ->
    binary:list_to_bin(tuple_to_list(Addr)).

bytes_to_ipv6_addr(Bytes) ->
    bytes_to_ipv6_addr([], Bytes).
bytes_to_ipv6_addr(Acc, <<H:2/binary, T/binary>>) ->
    bytes_to_ipv6_addr(Acc ++ [binary:decode_unsigned(H)], T);
bytes_to_ipv6_addr(Acc, <<>>) ->
    list_to_tuple(Acc).

% convert integer to 2-byte unsigned binary
integer_to_2byte_binary(Integer) ->
    Bytes = binary:encode_unsigned(Integer),
    case byte_size(Bytes) of
        1 ->
            <<0, Bytes/binary>>;
        2 ->
            Bytes
    end.


% figre address type by bytes
bytes_to_atyp(Bytes) ->
    case byte_size(Bytes) of
        4 ->
            ?ATYP_IPV4;
        8 ->
            ?ATYP_IPV6;
        _ ->
            ?ATYP_DOMAINNAME
    end.