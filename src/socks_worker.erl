-module(socks_worker).
-behaviour(gen_server).

-export([start_link/2]).
-export([send/2]). % used to send messages to connected client through the server
-export([close/2]). % used to indicate worker that connector socket has been closed
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).

-record(state, {supervisor, socket, destinationhost, connectorbuf = <<>>, sourcebuf = <<>>}).

-define(VER, <<5>>). % PROTOCOL VERSION 5
-define(M_NOAUTH , <<0>>). % NO AUTHENTICATION REQUIRED
-define(M_NOTAVAILABLE , <<255>>). % NO ACCEPTABLE METHODS
-define(CMD_CONNECT, <<1>>). % CONNECT '01'
-define(ATYP_IPV4, <<1>>). % IP V4 address '01'
-define(ATYP_DOMAINNAME, <<3>>). % DOMAINNAME '03'



start_link(Socket, Supervisor) ->
    gen_server:start_link(?MODULE, [Socket, Supervisor], []).

init([Socket, Supervisor]) ->
    %% Start accepting requests
    %% We must cast this to the worker's process, as it blocks it.
    gen_server:cast(self(), accept),
    {ok, #state{socket=Socket, supervisor=Supervisor}}.

% handle start message from self
handle_cast(accept, State) ->
    {ok, AcceptSocket} = gen_tcp:accept(State#state.socket),
    io:format("Worker: Accepted connection!~n", []),
    esocksd_sup:start_socket(State#state.supervisor), % start a new listener to replace this one
    %{ok, Connector} = osp_connector_server:start_link(self(), State#state.destinationhost, State#state.dstport), % start connector for this worker
    {noreply, #state{socket=AcceptSocket }};
% handle message from connector
handle_cast({send, _Msg}, State) ->
    {noreply, State};
% handle closed connector socket to DestinationHost
handle_cast({close, _Reason}, State) ->
    {stop, normal, State};
handle_cast(_, State) ->
    {noreply, State}.


% API function to send message to connected client
send(Pid, Msg) ->
    gen_server:cast(Pid, {send, Msg}).

% API function to notify worker that connector socket has been closed or there has been an error
close(Pid, Reason) ->
    gen_server:cast(Pid, {close, Reason}).

% handle messages from source
handle_info({tcp, Socket, _Msg}, State) ->
    ok = inet:setopts(Socket, [{active, once}]), % set as active once again
    io:format("Worker: Received something!~n", []),
    {noreply, State};
handle_info(E, State) ->
    io:fwrite("unexpected: ~p~n", [E]),
    {noreply, State}.

handle_call(_E, _From, State) -> {noreply, State}.
terminate(_Reason, _Tab) -> ok.
code_change(_OldVersion, Tab, _Extra) -> {ok, Tab}.


%%% helpers
subnegotiation() ->
    % receive version identifier/method selection

    asd.