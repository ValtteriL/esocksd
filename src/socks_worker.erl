-module(socks_worker).
-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).

-record(stage,{
    negotiate,
    authenticate,
    request,
    connect,
    udp_associate,
    destroy
}).
-record(state, {socket, connectsocket, stage = #stage.negotiate}).

% defined values for METHOD
-define(M_NOAUTH , 0). % NO AUTHENTICATION REQUIRED
-define(M_GSSAPI , 1).
-define(M_USERPASS , 2).
-define(SUPPORTED_VERSIONS , [5]).
-define(SUPPORTED_METHODS, [?M_NOAUTH]).

-define(M_NOTAVAILABLE , 255). % NO ACCEPTABLE METHODS
-define(RSV, 0). % Reserved

-define(ATYP_IPV4, 1). % IP V4 address '01'
-define(ATYP_IPV6, 4). % IP V6 address '04'
-define(ATYP_DOMAINNAME, 3). % DOMAINNAME '03'

-define(CMD_CONNECT, 1).  % CONNECT '01'
-define(CMD_BIND, 2).  % BIND '02'
-define(CMD_UDP_ASSOCIATE, 3).  % UDP ASSOCIATE '03'

-define(REP_SUCCESS, 0).
-define(REP_GEN_FAILURE, 1).
-define(REP_CONNECTION_NOT_ALLOWED, 2).
-define(REP_NETWORK_UNREACHABLE, 3).
-define(REP_HOST_UNREACHABLE, 4).
-define(REP_CONN_REFUSED, 5).
-define(REP_TTL_EXPIRED, 6).
-define(REP_CMD_NOT_SUPPORTED, 7).
-define(REP_ATYPE_NOT_SUPPORTED, 8).


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
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.negotiate}) ->

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
            {DST, T};
        ?ATYP_DOMAINNAME ->
            <<DOMAIN_LEN, T1/binary>> = Rest,
            <<DST:DOMAIN_LEN/binary, T/binary>> = T1,
            {DST, T};
        ?ATYP_IPV6 ->
            <<DST:16/binary, T/binary>> = Rest,
            {DST, T};
        _ ->
            io:fwrite("Worker: Unsupported ATYP received~n"),
            gen_tcp:send(State#state.socket, <<5, ?REP_ATYPE_NOT_SUPPORTED, ?RSV>>),
            gen_tcp:shutdown(State#state.socket, write)
    end,

    io:format("Worker: CMD: ~B, ATYP: ~B, DST_ADDR: ~p, DST_PORT: ~B~n", [CMD, ATYP, four_bytes_to_ipv4(DST_ADDR), binary:decode_unsigned(DST_PORT)]),

    case CMD of
        ?CMD_CONNECT ->
            io:fwrite("Worker: CONNECT request received~n"),
            connect(four_bytes_to_ipv4(DST_ADDR), binary:decode_unsigned(DST_PORT), State);
        ?CMD_BIND ->
            io:fwrite("Worker: BIN request received~n"),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State};
        ?CMD_UDP_ASSOCIATE ->
            io:fwrite("Worker: UDP ASSOCIATE request received~n"),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State};
        _->
            io:fwrite("Worker: Unsupported CMD received~n"),
            gen_tcp:send(State#state.socket, <<5, ?REP_CMD_NOT_SUPPORTED, ?RSV>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end;
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.connect, socket=Socket}) ->
    ok = inet:setopts(Socket, [{active, once}]),
    io:format("Worker: CONNECT (passing data from client to destination)~n", []),
    gen_tcp:send(State#state.connectsocket, Msg),
    {noreply, State};
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.connect, connectsocket=Socket}) ->
    ok = inet:setopts(Socket, [{active, once}]),
    io:format("Worker: CONNECT (passing data from destination to client)~n", []),
    gen_tcp:send(State#state.socket, Msg),
    {noreply, State};
handle_info({tcp_closed, _Socket}, State) -> {stop, normal, State};
handle_info({tcp_error, _Socket, _}, State) -> {stop, normal, State};
handle_info(E, State) ->
    io:fwrite("unexpected: ~p~n", [E]),
    {noreply, State}.

handle_call(_E, _From, State) -> {noreply, State}.
terminate(_Reason, _Tab) -> ok.
code_change(_OldVersion, Tab, _Extra) -> {ok, Tab}.


%%% helpers



% handle CONNECT command
connect(DST_ADDR, DST_PORT, State) ->
    case  gen_tcp:connect(DST_ADDR, DST_PORT, [], 5000) of
        {ok, Socket} ->
            io:fwrite("Worker: Connected!~n"),
            gen_tcp:send(State#state.socket, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, 127,0,0,1, 0,53>>),
            ok = inet:setopts(Socket, [{active, once}]),
            {noreply, State#state{stage=#stage.connect, connectsocket=Socket}};
        {error, Reason} ->
            case Reason of
                enetunreach -> gen_tcp:send(State#state.socket, <<5, ?REP_NETWORK_UNREACHABLE, ?RSV>>);
                ehostunreach -> gen_tcp:send(State#state.socket, <<5, ?REP_HOST_UNREACHABLE, ?RSV>>);
                econnrefused -> gen_tcp:send(State#state.socket, <<5, ?REP_CONN_REFUSED, ?RSV>>);
                _ -> gen_tcp:send(State#state.socket, <<5, ?REP_GEN_FAILURE, ?RSV>>)
            end,
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end.


% convert 4 bytes into tuple representation of IP address
four_bytes_to_ipv4(Bytes) ->
    [A, B, C, D] = binary:bin_to_list(Bytes),
    {A, B, C, D}.