-module(test_helpers).
-export([spawn_echoserver/0, server_loop/1, echo_loop/1]).

%%% Helpers

% spawn echo server on Port for testing purposes
spawn_echoserver() ->
    % ipv4
    {ok, ListenSocket} = gen_tcp:listen(0, [binary, inet, {reuseaddr, true}]),
    Handler = spawn(fun() -> 
        server_loop(ListenSocket)
    end),
    gen_tcp:controlling_process(ListenSocket, Handler),
    {ok, Port} = inet:port(ListenSocket),

    % ipv6
    {ok, ListenSocket2} = gen_tcp:listen(Port, [binary, inet6, {reuseaddr, true}]),
    Handler2 = spawn(fun() -> 
        server_loop(ListenSocket2)
    end),
    gen_tcp:controlling_process(ListenSocket2, Handler2),

    Port.

server_loop(Socket) ->
    {ok, Connection} = gen_tcp:accept(Socket),
    Handler = spawn(fun () -> echo_loop(Connection) end),
    gen_tcp:controlling_process(Connection, Handler),
    server_loop(Socket).

echo_loop(Connection) ->
    receive
        {tcp, Connection, Data} ->
	        gen_tcp:send(Connection, Data),
	        echo_loop(Connection)
    end.
