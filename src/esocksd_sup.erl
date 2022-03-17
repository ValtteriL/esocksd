%%%-------------------------------------------------------------------
%% @doc esocksd top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(esocksd_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).
-export([start_socket/1]).
-export([empty_listeners/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).


init([]) ->

     % listen on port, deliver received packets as binary, use socket for ipv4
    {ok, Listen} = gen_tcp:listen(9999, [binary, inet, {active, once}]),

    % create 5 worker processes (restart = temporary, so a child process is never restarted)
    Pid = self(),
    spawn_link(?MODULE, empty_listeners, [Pid]),

    SupFlags = #{strategy => simple_one_for_one, intensity => 1, period => 5},
    ChildSpecs = [#{ id => worker, start => {socks_worker, start_link, [Listen, self()]}, restart => temporary }],

    io:format("Listening for SOCKS connections~n", []),

    {ok, {SupFlags, ChildSpecs}}.

%% internal functions
start_socket(Pid) ->
    supervisor:start_child(Pid, []).

%% Start with 5 listeners so that many multiple connections can
%% be started at once, without serialization. In best circumstances,
%% a process would keep the count active at all times to insure nothing
%% bad happens over time when processes get killed too much.
empty_listeners(Pid) ->
    [start_socket(Pid) || _ <- lists:seq(1,5)],
    ok.