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
-record(state, {socket, connectsocket, stage = #stage.handshake, udpClientIP, udpClientPort}).

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
            {four_bytes_to_ipv4(DST), T};
        ?ATYP_DOMAINNAME ->
            <<DOMAIN_LEN, T1/binary>> = Rest,
            <<DST_HOST:DOMAIN_LEN/binary, T/binary>> = T1,
            {ok,{hostent,_,_,inet,4,[DST|_T]}} = inet:gethostbyname(binary_to_list(DST_HOST)),
            {DST, T};
        ?ATYP_IPV6 ->
            <<DST:16/binary, T/binary>> = Rest,
            {DST, T};
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
    gen_tcp:send(State#state.connectsocket, Msg),
    {noreply, State};
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.connect, connectsocket=Socket}) ->
    ok = inet:setopts(Socket, [{active, once}]),
    io:format("Worker: passing TCP data from destination to client~n", []),
    gen_tcp:send(State#state.socket, Msg),
    {noreply, State};
handle_info({tcp_closed, _Socket}, State) -> {stop, normal, State};
handle_info({tcp_error, _Socket, _}, State) -> {stop, normal, State};

% UDP port receives data with header
% UDP port receives data without header
handle_info({udp, Socket, Msg}, State=#state{stage=#stage.udp_associate, connectsocket=Socket}) ->
    ok = inet:setopts(Socket, [{active, once}]),
    io:format("Worker: passing UDP data from client to destination~n", []),

    {ok,{RemoteAddr, RemotePort}} = inet:peername(Socket),

    % expect encapsulated traffic from client
    case RemoteAddr == State#state.udpClientIP of
        true ->
            % client sent this (store the Port)
            <<?RSV, ?RSV, ?UDP_FRAG,  ATYP, Rest/binary>> = Msg,
            {DST_ADDR, DST_PORT, Data} = case ATYP of
                ?ATYP_IPV4 ->
                    <<DST:4/binary, T:2/binary, Datagram/binary>> = Rest,
                    {four_bytes_to_ipv4(DST), T, Datagram};
                ?ATYP_DOMAINNAME ->
                    <<DOMAIN_LEN, T1/binary>> = Rest,
                    <<DST_HOST:DOMAIN_LEN/binary, T:2/binary, Datagram/binary>> = T1,
                    {ok,{hostent,_,_,inet,4,[DST|_T]}} = inet:gethostbyname(binary_to_list(DST_HOST)),
                    {DST, T, Datagram};
                ?ATYP_IPV6 ->
                    <<DST:16/binary, T:2/binary, Datagram/binary>> = Rest,
                    {DST, T, Datagram}
            end,
            % relay Data to the destination
            gen_udp:send(Socket, {DST_ADDR, binary:decode_unsigned(DST_PORT)}, Data),
            {noreply, State=#state{udpClientPort=RemotePort}};
        _->
            % this is reply from the destination host
            % prepend header and send to client
            RemoteAddrBytes = ipv4_to_four_bytes(RemoteAddr),
            RemotePortBytes = integer_to_2byte_binary(RemotePort),
            Data = <<?UDP_RSV/binary, ?UDP_FRAG, RemoteAddrBytes/binary, RemotePortBytes/binary, Msg>>,
            gen_udp:send(Socket, {State#state.udpClientIP, State#state.udpClientPort}, Data),
            {noreply, State}
    end;


handle_info(E, State) ->
    io:fwrite("unexpected: ~p~n", [E]),
    {noreply, State}.

handle_call(_E, _From, State) -> {noreply, State}.
terminate(_Reason, _Tab) -> ok.
code_change(_OldVersion, Tab, _Extra) -> {ok, Tab}.


%%% helpers



% handle CONNECT command
% connects to a remote host
% stores the socket to connectsocket in state
% then relay traffic between socket and connectsocket
connect(DST_ADDR, DST_PORT, State) ->
    case  gen_tcp:connect(DST_ADDR, DST_PORT, [], 5000) of
        {ok, Socket} ->
            io:fwrite("Worker: Connected!~n"),

            {ok, {IfAddr, Port}} = inet:sockname(Socket),
            PortBytes = integer_to_2byte_binary(Port),
            IfAddrBytes = ipv4_to_four_bytes(IfAddr),
            
            % communicate the bound hostname and port
            gen_tcp:send(State#state.socket, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes/binary, PortBytes/binary>>),

            % convert received data to Erlang messages
            ok = inet:setopts(Socket, [{active, once}]),
            
            {noreply, State#state{stage=#stage.connect, connectsocket=Socket}};
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
% stores the listening socket to connectsocket
% once connection received relay traffic between socket and connectsocket
bind(State) ->
    % bind socket on random tcp port
    {ok, ListenSocket} = gen_tcp:listen(0, []),
    {ok, {IfAddr, Port}} = inet:sockname(ListenSocket),

    io:fwrite("Worker: Listening for connections on port ~B...~n", [Port]),

    PortBytes = integer_to_2byte_binary(Port),
    IfAddrBytes = ipv4_to_four_bytes(IfAddr),

    % communicate the bound hostname and port
    gen_tcp:send(<<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes/binary, PortBytes/binary>>),

    % wait for connection to the socket
    case gen_tcp:accept(ListenSocket, 60*1000*1) of
        {ok, Socket} ->

            io:fwrite("Worker: Connection accepted~n", []),

            % convert received data to Erlang messages
            ok = inet:setopts(Socket, [{active, once}]),

            % get peer info
            {ok,{RemoteAddr,RemotePort}} = inet:peername(Socket),
            RemoteAddrBytes = ipv4_to_four_bytes(RemoteAddr),
            RemotePortBytes = integer_to_2byte_binary(RemotePort),

            io:fwrite("Worker: Connection received from ~p:~B!~n", [RemoteAddr, RemotePort]),

            % communicate the received connection and peer details
            gen_tcp:send(State#state.socket, <<5, ?REP_SUCCESS, ?RSV, RemoteAddrBytes/binary, RemotePortBytes/binary>>),
            {noreply, State#state{stage=#stage.connect, connectsocket=Socket}};
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
    % bind socket on random udp port
    {ok, ListenSocket} = gen_udp:listen(0),
    {ok, {IfAddr, Port}} = inet:sockname(ListenSocket),

    io:fwrite("Worker: Listening for UDP connections on ~p, port ~B...~n", [IfAddr,Port]),

    PortBytes = integer_to_2byte_binary(Port),
    IfAddrBytes = ipv4_to_four_bytes(IfAddr),

    % communicate the bound hostname and port
    gen_tcp:send(<<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes/binary, PortBytes/binary>>),

    % convert received data to Erlang messages
    ok = inet:setopts(ListenSocket, [{active, once}]),

    UDPClient = case {DST_ADDR, DST_PORT} of
        {{0,0,0,0}, 0} ->
            % client does not know which IP:Port it will use - use the client IP 
            {ok,{RemoteAddr,_RemotePort}} = inet:peername(State#state.socket),
            RemoteAddr;
        _ ->
            % client uses this IP to send UDP traffic
            DST_ADDR
    end,

    % store the ListenSocket and used IP
    {noreply, State#state{stage=#stage.udp_associate, connectsocket=ListenSocket, udpClientIP=UDPClient}}.


% convert 4 bytes into tuple representation of IP address
four_bytes_to_ipv4(Bytes) ->
    [A, B, C, D] = binary:bin_to_list(Bytes),
    {A, B, C, D}.

ipv4_to_four_bytes({A,B,C,D}) ->
     binary:list_to_bin([A, B,C,D]).

% convert integer to 2-byte unsigned binary
integer_to_2byte_binary(Integer) ->
    Bytes = binary:encode_unsigned(Integer),
    case byte_size(Bytes) of
        1 ->
            <<0, Bytes/binary>>;
        2 ->
            Bytes
    end.
