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

%   SEND:
%            +----+----------+----------+
%            |VER | NMETHODS | METHODS  |
%            +----+----------+----------+
%            | 1  |    1     | 1 to 255 |
%            +----+----------+----------+
%
%   RECEIVE:
%           +----+--------+
%            |VER | METHOD |
%            +----+--------+
%            | 1  |   1    |
%            +----+--------+


% Handshake with noauth succeeds
handshake(_Config) ->
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 9999, [{active, false}, binary]),
    ok = gen_tcp:send(Socket, <<5, 1, ?M_NOAUTH>>),
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

% CONNECT request by ipv4 address succeeds
connect_ipv4(_Config) ->
    1=2.

% CONNECT request by ipv6 address succeeds
connect_ipv6(_Config) ->
    1=2.

% CONNECT request by domain resolving to ipv4 address succeeds
connect_domain_ipv4(_Config) ->
    1=2.

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