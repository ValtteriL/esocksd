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
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 1080, [{active, false}, binary]),
    ok = gen_tcp:send(Socket, ?HandshakeNoAuth),
    {ok, Packet} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),
    <<5, ?M_NOAUTH>> = Packet.

% Handshake without methods fails
handshake_without_methods(_Config) ->
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 1080, [{active, false}, binary]),
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


do_handshake_noauth() ->

    % connect to SOCKS host and do handshake with NOAUTH
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, 1080, [{active, false}, binary]),
    ok = gen_tcp:send(Socket, ?HandshakeNoAuth),
    {ok, <<5, ?M_NOAUTH>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),
    Socket.


% CONNECT request by ipv4 address succeeds
connect_ipv4(Config) ->

    % get echoserver port in binary and do handshake with SOCKS server
    BinPort = helpers:integer_to_2byte_binary(?config(echoport, Config)),
    Socket = do_handshake_noauth(),

    % request to CONNECT to the echo server on ipv4 address
    ok = gen_tcp:send(Socket, <<5, ?CMD_CONNECT, ?RSV, ?ATYP_IPV4, 127,0,0,1, BinPort/binary>>),
    {ok, ?ReplySuccessIpv4} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the echo server through SOCKS and verify it echoes back correctly
    Msg = <<"HELO">>,
    ok = gen_tcp:send(Socket, Msg),
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).


% CONNECT request by ipv6 address succeeds
connect_ipv6(Config) ->
    
    % get echoserver port in binary and do handshake with SOCKS server
    BinPort = helpers:integer_to_2byte_binary(?config(echoport, Config)),
    Socket = do_handshake_noauth(),

    % request to CONNECT to the echo server on ipv6 address
    ok = gen_tcp:send(Socket, <<5, ?CMD_CONNECT, ?RSV, ?ATYP_IPV6, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1, BinPort/binary>>),
    {ok, ?ReplySuccessIpv4} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the echo server through SOCKS and verify it echoes back correctly
    Msg = <<"HELO">>,
    ok = gen_tcp:send(Socket, Msg),
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).

% CONNECT request by domain resolving to ipv4 address succeeds
connect_domain_ipv4(Config) ->

    % get echoserver port in binary and do handshake with SOCKS server
    BinPort = helpers:integer_to_2byte_binary(?config(echoport, Config)),
    Socket = do_handshake_noauth(),

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
connect_domain_ipv6(Config) ->
    
    % get echoserver port in binary and do handshake with SOCKS server
    BinPort = helpers:integer_to_2byte_binary(?config(echoport, Config)),
    Socket = do_handshake_noauth(),

    % request to CONNECT to the echo server on ipv4 address
    Domain = <<"ip6-localhost">>,
    NDomain = byte_size(Domain),
    ok = gen_tcp:send(Socket, <<5, ?CMD_CONNECT, ?RSV, ?ATYP_DOMAINNAME, NDomain, Domain/binary, BinPort/binary>>),
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
%            +----+-----+-------+------+----------+----------+
%            |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
%            +----+-----+-------+------+----------+----------+
%            | 1  |  1  | X'00' |  1   | Variable |    2     |
%            +----+-----+-------+------+----------+----------+
%
%   RECEIVE (2x):
%            +----+-----+-------+------+----------+----------+
%            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
%            +----+-----+-------+------+----------+----------+
%            | 1  |  1  | X'00' |  1   | Variable |    2     |
%            +----+-----+-------+------+----------+----------+
%


% binding works when ipv4 address in request
bind_ipv4(_Config) ->

    % do handshake with SOCKS server
    Socket = do_handshake_noauth(),

    % request BIND
    ok = gen_tcp:send(Socket, <<5, ?CMD_BIND, ?RSV, ?ATYP_IPV4, 127,0,0,1, 0,0>>),
    {ok, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, _IfAddrBytes:4/binary, PortBytes:2/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % connect to the bound port
    Msg = <<"HELO">>,
    {ok, BindSock} = gen_tcp:connect("127.0.0.1", binary:decode_unsigned(PortBytes), [binary, {active, false}]),

    % receive message from SOCKS proxy informing about the connection
    {ok, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, _ClientIP:4/binary, _ClientPort:2/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the bound port
    ok = gen_tcp:send(BindSock, Msg),

    % receive the message from SOCKS proxy
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send the message to SOCKS proxy
    ok = gen_tcp:send(Socket, Msg),

    % receive the message from the Bound port socket
    {ok, Msg} = gen_tcp:recv(BindSock, 0, ?TimeoutMilliSec).

% binding works when ipv6 address in request
bind_ipv6(_Config) ->
        
    % do handshake with SOCKS server
    Socket = do_handshake_noauth(),

    % request BIND
    ok = gen_tcp:send(Socket, <<5, ?CMD_BIND, ?RSV, ?ATYP_IPV6, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1, 0,0>>),
    {ok, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, _IfAddrBytes:4/binary, PortBytes:2/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % connect to the bound port
    Msg = <<"HELO">>,
    {ok, BindSock} = gen_tcp:connect("127.0.0.1", binary:decode_unsigned(PortBytes), [binary, {active, false}]),

    % receive message from SOCKS proxy informing about the connection
    {ok, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, _ClientIP:4/binary, _ClientPort:2/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

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
    Socket = do_handshake_noauth(),

    Domain = <<"ip6-localhost">>,
    NDomain = byte_size(Domain),

    % request BIND
    ok = gen_tcp:send(Socket, <<5, ?CMD_BIND, ?RSV, ?ATYP_DOMAINNAME, NDomain, Domain/binary, 0,0>>),
    {ok, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, _IfAddrBytes:4/binary, PortBytes:2/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % connect to the bound port
    Msg = <<"HELO">>,
    {ok, BindSock} = gen_tcp:connect("127.0.0.1", binary:decode_unsigned(PortBytes), [binary, {active, false}]),

    % receive message from SOCKS proxy informing about the connection
    {ok, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, _ClientIP:4/binary, _ClientPort:2/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the bound port
    ok = gen_tcp:send(BindSock, Msg),

    % receive the message from SOCKS proxy
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send the message to SOCKS proxy
    ok = gen_tcp:send(Socket, Msg),

    % receive the message from the Bound port socket
    {ok, Msg} = gen_tcp:recv(BindSock, 0, ?TimeoutMilliSec).

%%%%%%%%
%
% UDP ASSOCIATE request
%
%%%%%%%%
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
%

% udp associate works when ipv4 address in request
udpassociate_ipv4(_Config) ->
    
    % do handshake with SOCKS server
    Socket = do_handshake_noauth(),

    % request UDP ASSOCIATE
    ok = gen_tcp:send(Socket, <<5, ?CMD_UDP_ASSOCIATE, ?RSV, ?ATYP_IPV4, 0,0,0,0, 0,0>>),
    {ok, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes:4/binary, PortBytes:2/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),
    
    % create two udp sockets - first to act as the socks client, second as the destination host
    {ok, ClientUdpSocket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:connect(ClientUdpSocket, helpers:bytes_to_addr(IfAddrBytes), binary:decode_unsigned(PortBytes)),

    {ok, ServerUdpSocket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:connect(ServerUdpSocket, helpers:bytes_to_addr(IfAddrBytes), binary:decode_unsigned(PortBytes)),

    % send message to server socket via SOCKS associate
    {ok, Port} = inet:port(ServerUdpSocket),
    Msg = <<"HELO">>,
    OwnPortBytes = helpers:integer_to_2byte_binary(Port),
    HdrMsg = <<?RSV, ?RSV, ?UDP_FRAG, ?ATYP_IPV4, 127,0,0,1, OwnPortBytes/binary, Msg/binary>>,

    ok = gen_udp:send(ClientUdpSocket, HdrMsg),

    % receive the msg from client at server side (without headers)
    {ok, {_Address, _Port, Msg}} = gen_udp:recv(ServerUdpSocket, 0, ?TimeoutMilliSec),

    % send msg from server to the client side
    ok = gen_udp:send(ServerUdpSocket, Msg),

    % receive the msg at client side (with headers)
    {ok, {_Address, _Port, HdrMsg2}} = gen_udp:recv(ClientUdpSocket, 0, ?TimeoutMilliSec),
    <<?RSV, ?RSV, ?UDP_FRAG, ?ATYP_IPV4, _RemoteAddrBytes:4/binary, OwnPortBytes:2/binary, Msg/binary>> = HdrMsg2.


% udp associate works when ipv6 address in request
udpassociate_ipv6(_Config) ->
        
    % do handshake with SOCKS server
    Socket = do_handshake_noauth(),

    % request UDP ASSOCIATE
    ok = gen_tcp:send(Socket, <<5, ?CMD_UDP_ASSOCIATE, ?RSV, ?ATYP_IPV6, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0>>),
    {ok, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes:4/binary, PortBytes:2/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),
    
    % create two udp sockets - first to act as the socks client, second as the destination host
    {ok, ClientUdpSocket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:connect(ClientUdpSocket, helpers:bytes_to_addr(IfAddrBytes), binary:decode_unsigned(PortBytes)),

    {ok, ServerUdpSocket} = gen_udp:open(0, [binary, inet6, {active, false}]),
    %ok = gen_udp:connect(ServerUdpSocket, {0,0,0,0,0,0,0,1}, binary:decode_unsigned(PortBytes)),

    % send message to server socket via SOCKS associate
    {ok, Port} = inet:port(ServerUdpSocket),
    Msg = <<"HELO">>,
    OwnPortBytes = helpers:integer_to_2byte_binary(Port),
    HdrMsg = <<?RSV, ?RSV, ?UDP_FRAG, ?ATYP_IPV6, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1, OwnPortBytes/binary, Msg/binary>>,

    ok = gen_udp:send(ClientUdpSocket, HdrMsg),

    % receive the msg from client at server side (without headers)
    {ok, {_Address, _Port, Msg}} = gen_udp:recv(ServerUdpSocket, 0, ?TimeoutMilliSec),

    % send msg from server to the client side
    ok = gen_udp:send(ServerUdpSocket, {0,0,0,0,0,0,0,1}, binary:decode_unsigned(PortBytes), Msg),

    % receive the msg at client side (with headers)
    {ok, {_Address2, _Port2, HdrMsg2}} = gen_udp:recv(ClientUdpSocket, 0, ?TimeoutMilliSec),
    <<?RSV, ?RSV, ?UDP_FRAG, ?ATYP_IPV6, _RemoteAddrBytes:16/binary, OwnPortBytes:2/binary, Msg/binary>> = HdrMsg2.

% udp associate works when domain address in request
udpassociate_domain(_Config) ->
    
    % do handshake with SOCKS server
    Socket = do_handshake_noauth(),

    % request UDP ASSOCIATE
    ok = gen_tcp:send(Socket, <<5, ?CMD_UDP_ASSOCIATE, ?RSV, ?ATYP_IPV4, 0,0,0,0, 0,0>>),
    {ok, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes:4/binary, PortBytes:2/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),
    
    % create two udp sockets - first to act as the socks client, second as the destination host
    {ok, ClientUdpSocket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:connect(ClientUdpSocket, helpers:bytes_to_addr(IfAddrBytes), binary:decode_unsigned(PortBytes)),

    {ok, ServerUdpSocket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:connect(ServerUdpSocket, helpers:bytes_to_addr(IfAddrBytes), binary:decode_unsigned(PortBytes)),

    % send message to server socket via SOCKS associate
    {ok, Port} = inet:port(ServerUdpSocket),
    Msg = <<"HELO">>,
    OwnPortBytes = helpers:integer_to_2byte_binary(Port),
    Domain = <<"localhost">>,
    DomainLength = byte_size(Domain),
    HdrMsg = <<?RSV, ?RSV, ?UDP_FRAG, ?ATYP_DOMAINNAME, DomainLength, Domain/binary, OwnPortBytes/binary, Msg/binary>>,

    ok = gen_udp:send(ClientUdpSocket, HdrMsg),

    % receive the msg from client at server side (without headers)
    {ok, {_Address, _Port, Msg}} = gen_udp:recv(ServerUdpSocket, 0, ?TimeoutMilliSec),

    % send msg from server to the client side
    ok = gen_udp:send(ServerUdpSocket, Msg),

    % receive the msg at client side (with headers)
    {ok, {_Address, _Port, HdrMsg2}} = gen_udp:recv(ClientUdpSocket, 0, ?TimeoutMilliSec),
    <<?RSV, ?RSV, ?UDP_FRAG, ?ATYP_IPV4, _RemoteAddrBytes:4/binary, OwnPortBytes:2/binary, Msg/binary>> = HdrMsg2.

