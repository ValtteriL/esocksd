-module(socks_worker).
-behaviour(gen_server).
-include("socks5.hrl").
-include("common.hrl").

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

    <<VER, _/binary>> = Msg,

    case VER of
        4 ->
            logger:debug("Worker: SOCKS4 chosen"),
            socks4:negotiate(Msg, State); % SOCKS4 does not include handshake - go directly to negotiation
        5 ->
            logger:debug("Worker: SOCKS5 chosen"),
            socks5:handshake(Msg, State)
    end;
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.request}) ->
    ok = inet:setopts(Socket, [{active, once}]),
    socks5:negotiate(Msg, State);
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

