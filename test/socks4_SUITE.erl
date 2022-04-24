-module(socks4_SUITE).
-include_lib("common_test/include/ct.hrl").
-include("src/socks4.hrl").
 
-export([all/0, init_per_suite/1, end_per_suite/1]).

-export([connect_ipv4/1, connect_domain_ipv4/1,
    bind_ipv4/1, bind_domain/1]).
 
all() -> [connect_ipv4, connect_domain_ipv4, bind_ipv4, bind_domain].
 
-define(TimeoutMilliSec, 10*1000).
-define(ReplySuccessIpv4, <<?REP_VERSION, ?REQ_GRANTED, _Rest/binary>>).


% start service
init_per_suite(Config) ->
    ok = application:load(esocksd),
    ok = application:start(esocksd),

    EchoPort = test_helpers:spawn_echoserver(), % spawn echo server for tests
    [{echoport, EchoPort}| Config].

% stop service
end_per_suite(Config) ->
    ok = application:stop(esocksd),
    ok = application:unload(esocksd),
    Config.


%%%%%%%%
%
% CONNECT request
%
%%%%%%%%
%
%   SEND:
%           +----+----+----+----+----+----+----+----+----+----+....+----+
%		    | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
%		    +----+----+----+----+----+----+----+----+----+----+....+----+
% bytes:	   1    1      2              4           variable       1
%
%   RECEIVE:
%           +----+----+----+----+----+----+----+----+
%		    | VN | CD | DSTPORT |      DSTIP        |
%           +----+----+----+----+----+----+----+----+
% bytes:	   1    1      2              4


% CONNECT request by ipv4 address succeeds
connect_ipv4(Config) ->

    % get echoserver port in binary and do handshake with SOCKS server
    BinPort = helpers:integer_to_2byte_binary(?config(echoport, Config)),

    % request to CONNECT to the echo server on ipv4 address
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 1080, [{active, false}, binary]),

    UserId = <<"dummy">>,
    ok = gen_tcp:send(Socket, <<4, ?CD_CONNECT, BinPort/binary, 127,0,0,1, UserId/binary, 0>>),
    {ok, ?ReplySuccessIpv4} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the echo server through SOCKS and verify it echoes back correctly
    Msg = <<"HELO">>,
    ok = gen_tcp:send(Socket, Msg),
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).


% CONNECT request by domain resolving to ipv4 address succeeds
connect_domain_ipv4(Config) ->

    % get echoserver port in binary and do handshake with SOCKS server
    BinPort = helpers:integer_to_2byte_binary(?config(echoport, Config)),
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 1080, [{active, false}, binary]),

    % request to CONNECT to the echo server on ipv4 address
    Domain = <<"localhost">>,
    UserId = <<"dummy">>,
    ok = gen_tcp:send(Socket, <<4, ?CD_CONNECT, BinPort/binary, 0,0,0,1, UserId/binary, 0, Domain/binary, 0>>),
    {ok, ?ReplySuccessIpv4} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the echo server through SOCKS and verify it echoes back correctly
    Msg = <<"HELO">>,
    ok = gen_tcp:send(Socket, Msg),
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).


%%%%%%%%
%
% BIND request
%
%%%%%%%%
%
%   SEND:
%           +----+----+----+----+----+----+----+----+----+----+....+----+
%		    | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
%		    +----+----+----+----+----+----+----+----+----+----+....+----+
% bytes:	   1    1      2              4           variable       1
%
%   RECEIVE (2x):
%           +----+----+----+----+----+----+----+----+
%		    | VN | CD | DSTPORT |      DSTIP        |
%           +----+----+----+----+----+----+----+----+
% bytes:	   1    1      2              4


% binding works when ipv4 address in request
bind_ipv4(_Config) ->

    % request BIND
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 1080, [{active, false}, binary]),

    UserId = <<"dummy">>,
    ok = gen_tcp:send(Socket, <<4, ?CD_BIND, 0,0, 127,0,0,1, UserId/binary, 0>>),
    {ok, <<?REP_VERSION, ?REQ_GRANTED, PortBytes:2/binary, _IfAddrBytes:4/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % connect to the bound port
    Msg = <<"HELO">>,
    {ok, BindSock} = gen_tcp:connect("127.0.0.1", binary:decode_unsigned(PortBytes), [binary, {active, false}]),

    % receive message from SOCKS proxy informing about the connection
    {ok, <<?REP_VERSION, ?REQ_GRANTED, _ClientPort:2/binary, _ClientIP:4/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the bound port
    ok = gen_tcp:send(BindSock, Msg),

    % receive the message from SOCKS proxy
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send the message to SOCKS proxy
    ok = gen_tcp:send(Socket, Msg),

    % receive the message from the Bound port socket
    {ok, Msg} = gen_tcp:recv(BindSock, 0, ?TimeoutMilliSec).


% binding works when domain address in request
bind_domain(_Config) ->
    
    % do handshake with SOCKS server
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 1080, [{active, false}, binary]),

    Domain = <<"localhost">>,
    UserId = <<"dummy">>,

    % request BIND
    ok = gen_tcp:send(Socket, <<4, ?CD_BIND, 0,0, 0,0,0,1, UserId/binary, 0, Domain/binary, 0>>),
    {ok, <<?REP_VERSION, ?REQ_GRANTED, PortBytes:2/binary, _IfAddrBytes:4/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % connect to the bound port
    Msg = <<"HELO">>,
    {ok, BindSock} = gen_tcp:connect("127.0.0.1", binary:decode_unsigned(PortBytes), [binary, {active, false}]),

    % receive message from SOCKS proxy informing about the connection
    {ok, <<?REP_VERSION, ?REQ_GRANTED, _ClientPort:2/binary, _ClientIP:4/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the bound port
    ok = gen_tcp:send(BindSock, Msg),

    % receive the message from SOCKS proxy
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send the message to SOCKS proxy
    ok = gen_tcp:send(Socket, Msg),

    % receive the message from the Bound port socket
    {ok, Msg} = gen_tcp:recv(BindSock, 0, ?TimeoutMilliSec).
