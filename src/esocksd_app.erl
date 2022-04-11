%%%-------------------------------------------------------------------
%% @doc esocksd public API
%% @end
%%%-------------------------------------------------------------------

-module(esocksd_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    config:load(),
    esocksd_sup_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
