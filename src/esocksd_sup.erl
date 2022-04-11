%%%-------------------------------------------------------------------
%% @doc esocksd second level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(esocksd_sup).

-behaviour(supervisor).

-export([start_link/1]).
-export([init/1]).
-export([start_socket/1]).
-export([empty_listeners/1]).

-define(SERVER, ?MODULE).

start_link(ListenAddress) ->
    supervisor:start_link(?MODULE, [ListenAddress]).

init([{Address, Port}]) ->

    Inet = case tuple_size(Address) of
        4 -> inet;
        8 -> inet6
    end,

    % listen on correct ip version, address, and port, deliver received packets as binary
    {ok, Listen} = gen_tcp:listen(Port, [{ip, Address}, binary, Inet, {active, once}]),

    % restart = temporary, so a child process is never restarted
    SupFlags = #{strategy => simple_one_for_one, intensity => 1, period => 5},
    ChildSpecs = [#{ id => worker, start => {socks_worker, start_link, [self(), Listen]}, restart => temporary }],

    % create 5 worker processes
    spawn_link(?MODULE, empty_listeners, [self()]),
    
    AddressString = inet:ntoa(Address),
    logger:notice("Listening for connections on ~s port ~B", [AddressString, Port]),

    {ok, {SupFlags, ChildSpecs}}.

%% internal functions
start_socket(Pid) ->
    {ok, _} = supervisor:start_child(Pid, []).

%% Start with 5 listeners so that many multiple connections can
%% be started at once, without serialization. In best circumstances,
%% a process would keep the count active at all times to insure nothing
%% bad happens over time when processes get killed too much.
empty_listeners(Pid) ->
    [start_socket(Pid) || _ <- lists:seq(1,5)],
    ok.