%%%-------------------------------------------------------------------
%% @doc esocksd top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(esocksd_sup_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    config:load(),
    logger:notice("### Starting esocksd ###"),
    ListenAddresses = config:listen_addresses(),

    % start supervisor for each listenaddress
    ChildSpecList = lists:map(fun(Address) ->
            % transient = restart child only if it terminates abnormally
            {Addr, _} = Address,
            Name = inet:ntoa(Addr) ++ ":" ++ integer_to_list(1080),
            #{ id => Name, start => {esocksd_sup, start_link, [Address]}, restart => transient }
        end, 
        ListenAddresses),

    SupFlags = #{strategy => one_for_one, intensity => 1, period => 5},

    {ok, {SupFlags, ChildSpecList}}.
