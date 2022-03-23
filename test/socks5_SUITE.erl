-module(socks5_SUITE).
-include_lib("common_test/include/ct.hrl").
-include("src/socks5.hrl").
 
-export([all/0, init_per_suite/1, end_per_suite/1]).

-export([handshake/1, handshake_without_methods/1,
    connect_ipv4/1, connect_ipv6/1, connect_domain_ipv4/1, connect_domain_ipv6/1,
    bind_ipv4/1, bind_ipv6/1, bind_domain/1,
    udpassociate_ipv4/1, udpassociate_ipv6/1, udpassociate_domain/1]).
 
all() -> [handshake, handshake_without_methods, connect_ipv4, connect_ipv6, connect_domain_ipv4, connect_domain_ipv6, bind_ipv4, bind_ipv6, bind_domain, udpassociate_ipv4, udpassociate_ipv6, udpassociate_domain].
 
-define(TimeoutMilliSec, 10*1000).
-define(HandshakeNoAuth, <<5, 1, ?M_NOAUTH>>).
-define(ReplySuccessIpv4, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, _Rest/binary>>).


% start service
init_per_suite(Config) ->
    {ok, App} = esocksd_app:start(does, notmatter),
    unlink(App), % unlink App to keep it running
    [{app, App}| Config].

% stop service
end_per_suite(Config) ->
    App = ?config(app, Config),
    exit(App, normal),
    Config.


%%%%%%%%
%
% Handshake
%
%%%%%%%%
%
%   SEND:
%            +----+----------+----------+
%            |VER | NMETHODS | METHODS  |
%            +----+----------+----------+
%            | 1  |    1     | 1 to 255 |
%            +----+----------+----------+
%
%   RECEIVE:
%            +----+--------+
%            |VER | METHOD |
%            +----+--------+
%            | 1  |   1    |
%            +----+--------+


% Handshake with noauth succeeds
handshake(_Config) ->
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 9999, [{active, false}, binary]),
    ok = gen_tcp:send(Socket, ?HandshakeNoAuth),
    {ok, Packet} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),
    <<5, ?M_NOAUTH>> = Packet.

% Handshake without methods fails
handshake_without_methods(_Config) ->
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 9999, [{active, false}, binary]),
    ok = gen_tcp:send(Socket, <<5, 0>>),
    {ok, Packet} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),
    <<5, ?M_NOTAVAILABLE>> = Packet.

%%%%%%%%
%
% CONNECT request
%
%%%%%%%%
%
%   SEND:
%            +----+-----+-------+------+----------+----------+
%            |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
%            +----+-----+-------+------+----------+----------+
%            | 1  |  1  | X'00' |  1   | Variable |    2     |
%            +----+-----+-------+------+----------+----------+
%
%   RECEIVE:
%            +----+-----+-------+------+----------+----------+
%            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
%            +----+-----+-------+------+----------+----------+
%            | 1  |  1  | X'00' |  1   | Variable |    2     |
%            +----+-----+-------+------+----------+----------+


% CONNECT request by ipv4 address succeeds
connect_ipv4(_Config) ->

    % start echo server on random port
    Port = spawn_echoserver(),
    BinPort = integer_to_2byte_binary(Port),

    % connect to SOCKS host and do handshake with NOAUTH
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 9999, [{active, false}, binary]),
    ok = gen_tcp:send(Socket, ?HandshakeNoAuth),
    {ok, <<5, ?M_NOAUTH>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % request to CONNECT to the echo server on ipv4 address
    ok = gen_tcp:send(Socket, <<5, ?CMD_CONNECT, ?RSV, ?ATYP_IPV4, 127,0,0,1, BinPort/binary>>),
    {ok, ?ReplySuccessIpv4} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the echo server through SOCKS and verify it echoes back correctly
    Msg = <<"HELO">>,
    ok = gen_tcp:send(Socket, Msg),
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).


% CONNECT request by ipv6 address succeeds
connect_ipv6(_Config) ->
    
    % start echo server on random port
    Port = spawn_echoserver(),
    BinPort = integer_to_2byte_binary(Port),

    % connect to SOCKS host and do handshake with NOAUTH
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 9999, [{active, false}, binary]),
    ok = gen_tcp:send(Socket, ?HandshakeNoAuth),
    {ok, <<5, ?M_NOAUTH>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % request to CONNECT to the echo server on ipv6 address
    ok = gen_tcp:send(Socket, <<5, ?CMD_CONNECT, ?RSV, ?ATYP_IPV6, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1, BinPort/binary>>),
    {ok, ?ReplySuccessIpv4} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the echo server through SOCKS and verify it echoes back correctly
    Msg = <<"HELO">>,
    ok = gen_tcp:send(Socket, Msg),
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).

% CONNECT request by domain resolving to ipv4 address succeeds
connect_domain_ipv4(_Config) ->
    % start echo server on random port
    Port = spawn_echoserver(),
    BinPort = integer_to_2byte_binary(Port),

    % connect to SOCKS host and do handshake with NOAUTH
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 9999, [{active, false}, binary]),
    ok = gen_tcp:send(Socket, ?HandshakeNoAuth),
    {ok, <<5, ?M_NOAUTH>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % request to CONNECT to the echo server on ipv4 address
    Domain = <<"localhost">>,
    NDomain = byte_size(Domain),
    ok = gen_tcp:send(Socket, <<5, ?CMD_CONNECT, ?RSV, ?ATYP_DOMAINNAME, NDomain, Domain/binary, BinPort/binary>>),
    {ok, ?ReplySuccessIpv4} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the echo server through SOCKS and verify it echoes back correctly
    Msg = <<"HELO">>,
    ok = gen_tcp:send(Socket, Msg),
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).

% CONNECT request by domain resolving to ipv6 address succeeds
connect_domain_ipv6(_Config) ->
    1=2.

%%%%%%%%
%
% BIND request
%
%%%%%%%%

% binding works when ipv4 address in request
bind_ipv4(_Config) ->
    1=2.

% binding works when ipv6 address in request
bind_ipv6(_Config) ->
    1=2.

% binding works when domain address in request
bind_domain(_Config) ->
    1=2.

%%%%%%%%
%
% UDP ASSOCIATE request
%
%%%%%%%%

% udp associate works when ipv4 address in request
udpassociate_ipv4(_Config) ->
    1=2.

% udp associate works when ipv6 address in request
udpassociate_ipv6(_Config) ->
    1=2.

% udp associate works when domain address in request
udpassociate_domain(_Config) ->
    1=2.



%%% Helpers

% spawn echo server on Port for testing purposes
spawn_echoserver() ->
    {ok, ListenSocket} = gen_tcp:listen(0, [binary]),
    spawn_link(fun() -> 
        {ok, Socket} = gen_tcp:accept(ListenSocket),
        receive
            {tcp, Socket, Data} ->
                gen_tcp:send(Socket, Data),
                ok = gen_tcp:shutdown(Socket, read)
        end
    end),
    {ok, Port} = inet:port(ListenSocket),
    Port.

% convert integer to 2-byte unsigned binary
integer_to_2byte_binary(Integer) ->
    Bytes = binary:encode_unsigned(Integer),
    case byte_size(Bytes) of
        1 ->
            <<0, Bytes/binary>>;
        2 ->
            Bytes
    end.