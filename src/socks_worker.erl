-module(socks_worker).
-behaviour(gen_server).
-include("socks5.hrl").
-include("common.hrl").

-export([start_link/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).


start_link(Supervisor, Socket) ->
    gen_server:start_link(?MODULE, [Supervisor, Socket], []).

init([Supervisor, Socket]) ->
    gen_server:cast(self(), accept),
    {ok, #state{supervisor=Supervisor, socket=Socket}}.

% handle start message from self
handle_cast(accept, State) ->

    % accept new connection
    {ok, AcceptSocket} = gen_tcp:accept(State#state.socket),
    logger:debug("Worker: Accepted connection"),

    esocksd_sup:start_socket(State#state.supervisor), % start a new listener to replace this one
    {noreply, #state{socket=AcceptSocket }};

handle_cast(_, State) ->
    {noreply, State}.


% handle tcp traffic
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.handshake}) ->

    ok = inet:setopts(Socket, [{active, once}]),
    logger:debug("Worker: Entered negotiation"),

    <<VER, _/binary>> = Msg,

    case {VER, config:auth_required()} of
        {4, true} ->
            % SOCKS4 attempted but authentication mandatory - close connection
            gen_tcp:shutdown(Socket, write),
            gen_tcp:close(Socket),
            {stop, normal, State};
        {4, false} ->
            % SOCKS4
            logger:debug("Worker: SOCKS4 chosen"),
            socks4:negotiate(Msg, State); % SOCKS4 does not include handshake - go directly to negotiation
        {5, _} ->
            % SOCKS5
            logger:debug("Worker: SOCKS5 chosen"),
            socks5:handshake(Msg, State)
    end;
handle_info({tcp, Socket, Msg}, State=#state{stage=#stage.authenticate}) ->
    ok = inet:setopts(Socket, [{active, once}]),
    socks5:authenticate(Msg, State);
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

handle_info(Message = {udp, _Socket, _IP, _InPortNo, _Msg}, State=#state{stage=#stage.udp_associate}) ->
    socks5:udp_associate_relay(Message, State);

handle_info(E, State) ->
    logger:warning("UNEXPECTED: ~p", [E]),
    {noreply, State}.

handle_call(_E, _From, State) -> {noreply, State}.
terminate(_Reason, _Tab) -> ok.
code_change(_OldVersion, Tab, _Extra) -> {ok, Tab}.


%%% helpers

