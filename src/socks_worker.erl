-module(socks_worker).
-behaviour(gen_server).
-include("socks5.hrl").

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).


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
    logger:debug("Worker: Accepted connection"),

    esocksd_sup:start_socket(), % start a new listener to replace this one
    {noreply, #state{socket=AcceptSocket }};

handle_cast(_, State) ->
    {noreply, State}.


% handle tcp traffic
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.handshake}) ->

    ok = inet:setopts(Socket, [{active, once}]),
    logger:debug("Worker: Entered negotiation"),

    <<VER, NMETHODS, METHODS/binary>> = Msg,
    logger:debug("Worker: Received initial message SOCKS version: ~B, NMETHODS: ~B~n", [VER, NMETHODS]),

    ListMETHODS = binary:bin_to_list(METHODS),

    % check version and proposed auth method
    case {lists:member(VER, ?SUPPORTED_VERSIONS), lists:member(?M_NOAUTH, ListMETHODS)}  of
        {true, true} ->
            % choose M_NOAUTH method, and move to next stage
            logger:debug("Worker: Supported SOCKS version and method found"),
            gen_tcp:send(State#state.socket, <<VER, ?M_NOAUTH>>),
            {noreply, State#state{stage=#stage.request}};
        {false, _} ->
            % reply no, end connection, and terminate worker
            logger:info("Worker: Unsupported SOCKS version"),
            gen_tcp:send(State#state.socket, <<5, ?M_NOTAVAILABLE>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State};
        _ -> 
            % reply no, end connection, and terminate worker
            logger:info("Worker: Unsupported auth method proposed"),
            gen_tcp:send(State#state.socket, <<VER, ?M_NOTAVAILABLE>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end;
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.request}) ->

    ok = inet:setopts(Socket, [{active, once}]),
    logger:debug("Worker: Received request"),

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

    logger:debug("Worker: CMD: ~B, ATYP: ~B, DST_ADDR: ~p, DST_PORT: ~B~n", [CMD, ATYP, DST_ADDR, binary:decode_unsigned(DST_PORT)]),

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
    end;
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.connect, socket=Socket}) ->
    ok = inet:setopts(Socket, [{active, once}]),
    logger:debug("Worker (in CONNECT): passing TCP data from client to destination"),
    gen_tcp:send(State#state.connectSocket, Msg),
    {noreply, State};
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.connect, connectSocket=Socket}) ->
    ok = inet:setopts(Socket, [{active, once}]),
    logger:debug("Worker (in CONNECT): passing TCP data from destination to client"),
    gen_tcp:send(State#state.socket, Msg),
    {noreply, State};
handle_info({tcp_closed, _Socket}, State) -> {stop, normal, State};
handle_info({tcp_error, _Socket, _}, State) -> {stop, normal, State};

% UDP port receives data with header
% UDP port receives data without header
handle_info({udp, Socket, IP, InPortNo, Msg}, State=#state{stage=#stage.udp_associate}) ->

    ok = inet:setopts(Socket, [{active, once}]),
    logger:debug("Worker (in UDP ASSOCIATE): passing UDP data"),

    % expect encapsulated traffic from client
    case ((IP == State#state.udpClientIP) and ((InPortNo == State#state.udpClientPort) or (State#state.udpClientPort==undefined))) of
        true ->
            logger:debug("Worker (in UDP ASSOCIATE): client sends UDP traffic to DST"),
            % client sent this (store the Port)
            <<?RSV, ?RSV, ?UDP_FRAG,  ATYP, Rest/binary>> = Msg,
            {DST_ADDR, DST_PORT, Data} = case ATYP of
                ?ATYP_IPV4 ->
                    <<DST:4/binary, T:2/binary, Datagram/binary>> = Rest,
                    {helpers:bytes_to_addr(DST), T, Datagram};
                ?ATYP_DOMAINNAME ->
                    <<DOMAIN_LEN, T1/binary>> = Rest,
                    <<DST_HOST:DOMAIN_LEN/binary, T:2/binary, Datagram/binary>> = T1,
                    DST = binary_to_list(DST_HOST),
                    {DST, T, Datagram};
                ?ATYP_IPV6 ->
                    <<DST:16/binary, T:2/binary, Datagram/binary>> = Rest,
                    {helpers:bytes_to_addr(DST), T, Datagram}
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

            logger:debug("Worker (in UDP ASSOCIATE): DST sends UDP traffic to client"),
            % this is reply from the destination host
            % prepend header and send to client
            
            RemoteAddrBytes = helpers:addr_to_bytes(IP),
            RemotePortBytes = helpers:integer_to_2byte_binary(InPortNo),

            % get type of address
            ATYP = helpers:bytes_to_atyp(RemoteAddrBytes),

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
    logger:warning("UNEXPECTED: ~p", [E]),
    {noreply, State}.

handle_call(_E, _From, State) -> {noreply, State}.
terminate(_Reason, _Tab) -> ok.
code_change(_OldVersion, Tab, _Extra) -> {ok, Tab}.


%%% helpers

