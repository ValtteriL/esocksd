-module(socks5).
-include("socks5.hrl").
-include("common.hrl").

-export([handshake/2, negotiate/2, connect/3, bind/1, udp_associate/3]).

% SOCKS5 + SOCKS5H related functions
% followed documents: 
% - https://datatracker.ietf.org/doc/html/rfc1928

handshake(Msg, State) ->
    <<5, NMETHODS, METHODS/binary>> = Msg,
    logger:debug("Worker: Received SOCKS5 handshake message with ~B methods", [NMETHODS]),

    ListMETHODS = binary:bin_to_list(METHODS),

    % check version and proposed auth method
    case lists:member(?M_NOAUTH, ListMETHODS)  of
        true ->
            % choose M_NOAUTH method, and move to next stage
            logger:debug("Worker: Supported SOCKS version and method found"),
            gen_tcp:send(State#state.socket, <<5, ?M_NOAUTH>>),
            {noreply, State#state{stage=#stage.request}};
        _ -> 
            % reply no, end connection, and terminate worker
            logger:info("Worker: Unsupported auth method proposed"),
            gen_tcp:send(State#state.socket, <<5, ?M_NOTAVAILABLE>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end.

negotiate(Msg, State) ->
    <<_VER, CMD, ?RSV, ATYP, Rest/binary>> = Msg,

    {DST_ADDR, DST_PORT} = case ATYP of
        ?ATYP_IPV4 ->
            <<DST:4/binary, T/binary>> = Rest,
            {helpers:bytes_to_addr(DST), T};
        ?ATYP_DOMAINNAME ->
            <<DOMAIN_LEN, T1/binary>> = Rest,
            <<DST_HOST:DOMAIN_LEN/binary, T/binary>> = T1,
            DST = binary_to_list(DST_HOST),
            {DST, T};
        ?ATYP_IPV6 ->
            <<DST:16/binary, T/binary>> = Rest,
            {helpers:bytes_to_addr(DST), T};
        _ ->
            logger:info("Worker: Unsupported ATYP reveived"),
            gen_tcp:send(State#state.socket, <<5, ?REP_ATYPE_NOT_SUPPORTED, ?RSV, ?REP_PADDING/binary>>),
            gen_tcp:shutdown(State#state.socket, write)
    end,

    logger:debug("Worker: Received SOCKS request CMD: ~B, ATYP: ~B, DST_ADDR: ~p, DST_PORT: ~B~n", [CMD, ATYP, DST_ADDR, binary:decode_unsigned(DST_PORT)]),

    case CMD of
        ?CMD_CONNECT ->
            logger:debug("Worker: CONNECT request received"),
            socks5:connect(DST_ADDR, binary:decode_unsigned(DST_PORT), State);
        ?CMD_BIND ->
            logger:debug("Worker: BIND request received"),
            socks5:bind(State);
        ?CMD_UDP_ASSOCIATE ->
            logger:debug("Worker: UDP ASSOCIATE request received"),
            socks5:udp_associate(DST_ADDR, binary:decode_unsigned(DST_PORT), State);
        _->
            logger:info("Worker: Unsupported CMD received"),
            gen_tcp:send(State#state.socket, <<5, ?REP_CMD_NOT_SUPPORTED, ?RSV, ?REP_PADDING/binary>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end.


% handle CONNECT command
% connects to a remote host
% stores the socket to connectSocket in state
% then relay traffic between socket and connectSocket
connect(DST_ADDR, DST_PORT, State) ->
    case  gen_tcp:connect(DST_ADDR, DST_PORT, [], 5000) of
        {ok, Socket} ->
            logger:debug("Worker (in CONNECT): Connection established to remote host!"),

            {ok, {IfAddr, Port}} = inet:sockname(Socket),
            PortBytes = helpers:integer_to_2byte_binary(Port),
            IfAddrBytes = helpers:addr_to_bytes(IfAddr),
            
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

    logger:debug("Worker (in BIND): Listening for connections on port ~B...~n", [Port]),

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

            logger:info("Worker: Connection received from ~p:~B!", [RemoteAddr, RemotePort]),

            % communicate the received connection and peer details
            gen_tcp:send(State#state.socket, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, RemoteAddrBytes/binary, RemotePortBytes/binary>>),
            {noreply, State#state{stage=#stage.connect, connectSocket=Socket}};
        {error, _} ->

            logger:info("Worker (in BIND): Error accepting connection"),

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

    logger:info("Worker (in UDP ASSOCIATE): Listening for UDP connections on ~p, port ~B", [IfAddr,Port]),

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

