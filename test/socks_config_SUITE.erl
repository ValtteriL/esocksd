-module(socks_config_SUITE).
-include_lib("common_test/include/ct.hrl").
-include("src/socks5.hrl").
-include("src/socks4.hrl").

% use correct listenaddress, port, and logfile
%
% authmethod userpass - socks4 disabled
% authmethod userpass - incorrect creds fail
% authmethod userpass - correct creds work
%
% commands allowed - disallowed dont work in socks4 - rest work
% commands allowed - disallowed dont work in socks5 - rest work
%
% network acl - disallowed dont work in socks4 - rest allowed
% network acl - disallowed dont work in socks5 - rest allowed

-export([all/0, init_per_suite/1, end_per_suite/1]).

-export([listenaddress_port_logfile/1, 
    authmethod_userpass_socks4_disabled/1, authmethod_userpass_correct_creds_work/1, authmethod_userpass_incorrect_creds_fail/1,
    allowed_commands_work/1, disallowed_commands_fail/1, 
    networkacl_disallowed_fail_connect/1, networkacl_disallowed_fail_udp_associate_known/1, 
    networkacl_disallowed_fail_udp_associate_unknown/1, networkacl_allowed_work/1]).
 
all() -> [listenaddress_port_logfile, 
    authmethod_userpass_socks4_disabled, authmethod_userpass_correct_creds_work, authmethod_userpass_incorrect_creds_fail,
    allowed_commands_work, disallowed_commands_fail, 
    networkacl_disallowed_fail_connect, networkacl_disallowed_fail_udp_associate_known, 
    networkacl_disallowed_fail_udp_associate_unknown, networkacl_allowed_work].
 
-define(TimeoutMilliSec, 10*1000).
-define(SmallTimeoutMilliSec, 1*1000).
-define(HandshakeNoAuth, <<5, 1, ?M_NOAUTH>>).
-define(HandshakeUserPass, <<5, 1, ?M_USERPASS>>).
-define(ReplySuccessIpv4, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, _Rest/binary>>).
-define(ReplyDisallowed, <<5, ?REP_CONNECTION_NOT_ALLOWED, ?RSV, ?ATYP_IPV4, _Rest/binary>>).
-define(AUTH_SUCCESS, 0).

% vars for custom config
-define(Port, 1081).
-define(Host, "127.0.0.2").
-define(HostTuple, {127,0,0,2}).
-define(Username, "user").
-define(Password, "secret").


% start service
init_per_suite(Config) ->

    % config for application in tests
    ConfigEnv = [
        {listenaddress, [?Host]}, 
        {port, [?Port]}, 
        {loglevel, debug}, 
        {logfile, "test-esocksd.log"}, 
        {authmethod, userpass},
        {allowcommands, [connect, udp_associate]},
        {networkacl, [
            {allow, "127.0.0.1/24"},
            {block, "0.0.0.0/0"}
        ]},
        {networkacl6, [
            {block, "::/0"}
        ]},
        {userpass, [
            {?Username, ?Password}
        ]}
    ],

    % start esocksd with the config
    ok = application:load(esocksd),
    ok = application:set_env([{esocksd, ConfigEnv}], []),
    ok = application:start(esocksd),

    EchoPort = test_helpers:spawn_echoserver(), % spawn echo server for tests
    [{echoport, EchoPort}| Config].

% stop service
end_per_suite(Config) ->
    ok = application:stop(esocksd),
    Config.

do_handshake_userpass() ->

    % connect to SOCKS host and do handshake with userpass
    {ok, Socket} = gen_tcp:connect(?HostTuple, ?Port, [{active, false}, binary]),
    ok = gen_tcp:send(Socket, ?HandshakeUserPass),
    {ok, <<5, ?M_USERPASS>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    {ok, Socket}.

do_auth(Socket, Username, Password) ->
    VER = 1,
    ULEN = string:length(Username),
    PLEN = string:length(Password),
    UNAME = list_to_binary(Username),
    PASSWD = list_to_binary(Password),
    ok = gen_tcp:send(Socket, <<VER, ULEN, UNAME/binary, PLEN, PASSWD/binary>>),
    {ok, <<VER, Status>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    case Status of
        ?AUTH_SUCCESS -> {ok, success};
        _-> {ok, fail}
    end.


%%%%%%%%
%
% listtenaddr, port, logfile
%
%%%%%%%%

listenaddress_port_logfile(_Config) ->
    
    % connect to server on specific address and port
    {ok, _Socket} = do_handshake_userpass(),

    % check that logfile exists
    {ok, _} = file:open("test-esocksd.log", [read]).


%%%%%%%%
%
% authmethod
%
%%%%%%%%

authmethod_userpass_socks4_disabled(_Config) -> 
    {ok, Socket} = gen_tcp:connect(?HostTuple, ?Port, [{active, false}, binary]),
    UserId = <<"dummy">>,
    ok = gen_tcp:send(Socket, <<4, ?CD_CONNECT, 443, 127,0,0,1, UserId/binary, 0>>),
    {error, closed} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).

authmethod_userpass_correct_creds_work(_Config) -> 
    {ok, Socket} = do_handshake_userpass(),
    {ok, success} = do_auth(Socket, ?Username, ?Password).

authmethod_userpass_incorrect_creds_fail(_Config) -> 
    {ok, Socket} = do_handshake_userpass(),
    {ok, fail} = do_auth(Socket, ?Username, "thisisincorrect").

%%%%%%%%
%
% allowing/disallowing commands
%
%%%%%%%%

allowed_commands_work(Config) -> 
    {ok, Socket} = do_handshake_userpass(),
    {ok, success} = do_auth(Socket, ?Username, ?Password),

    % get echoserver port in binary and do handshake with SOCKS server
    BinPort = helpers:integer_to_2byte_binary(?config(echoport, Config)),

    % request to CONNECT to the echo server on ipv4 address
    ok = gen_tcp:send(Socket, <<5, ?CMD_CONNECT, ?RSV, ?ATYP_IPV4, 127,0,0,1, BinPort/binary>>),
    {ok, ?ReplySuccessIpv4} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % send message to the echo server through SOCKS and verify it echoes back correctly
    Msg = <<"HELO">>,
    ok = gen_tcp:send(Socket, Msg),
    {ok, Msg} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).


disallowed_commands_fail(_Config) -> 
    {ok, Socket} = do_handshake_userpass(),
    {ok, success} = do_auth(Socket, ?Username, ?Password),

    % request BIND
    ok = gen_tcp:send(Socket, <<5, ?CMD_BIND, ?RSV, ?ATYP_IPV4, 127,0,0,1, 0,0>>),

    % get command not supported response
    {ok, <<5, ?REP_CMD_NOT_SUPPORTED, ?RSV, _Rest/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).

%%%%%%%%
%
% Network ACL
%
%%%%%%%%

networkacl_disallowed_fail_connect(_Config) -> 
    {ok, Socket} = do_handshake_userpass(),
    {ok, success} = do_auth(Socket, ?Username, ?Password),

    % request to CONNECT to a blocked IP address
    ok = gen_tcp:send(Socket, <<5, ?CMD_CONNECT, ?RSV, ?ATYP_IPV4, 8,8,8,8, 53>>),
    {ok, ?ReplyDisallowed} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).

networkacl_disallowed_fail_bind_socks5(_Config) -> ok.

networkacl_disallowed_fail_udp_associate_known(_Config) -> 
    {ok, Socket} = do_handshake_userpass(),
    {ok, success} = do_auth(Socket, ?Username, ?Password),

    % request to UDP ASSOCIATE to a known blocked IP address
    ok = gen_tcp:send(Socket, <<5, ?CMD_UDP_ASSOCIATE, ?RSV, ?ATYP_IPV4, 8,8,8,8, 5,3>>),
    {ok, ?ReplyDisallowed} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec).

networkacl_disallowed_fail_udp_associate_unknown(_Config) -> 
    {ok, Socket} = do_handshake_userpass(),
    {ok, success} = do_auth(Socket, ?Username, ?Password),

    % request to UDP ASSOCIATE without specifying destination
    ok = gen_tcp:send(Socket, <<5, ?CMD_UDP_ASSOCIATE, ?RSV, ?ATYP_IPV4, 0,0,0,0, 0,0>>),
    {ok, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes:4/binary, PortBytes:2/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),

    % create two udp sockets - first to act as the socks client, second as the destination host
    {ok, ClientUdpSocket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:connect(ClientUdpSocket, helpers:bytes_to_addr(IfAddrBytes), binary:decode_unsigned(PortBytes)),

    {ok, ServerUdpSocket} = gen_udp:open(0, [binary, {active, false}, {ifaddr, {127,0,1,1}}]), % 127.0.1.1 is disallowed by config
    ok = gen_udp:connect(ServerUdpSocket, helpers:bytes_to_addr(IfAddrBytes), binary:decode_unsigned(PortBytes)),

    % send message to server socket via SOCKS associate
    {ok, Port} = inet:port(ServerUdpSocket),
    Msg = <<"HELO">>,
    OwnPortBytes = helpers:integer_to_2byte_binary(Port),
    HdrMsg = <<?RSV, ?RSV, ?UDP_FRAG, ?ATYP_IPV4, 127,0,1,1, OwnPortBytes/binary, Msg/binary>>,

    ok = gen_udp:send(ClientUdpSocket, HdrMsg),

    % server should not receive anything as the SOCKS server drops packets to disallowed hosts
    {error, timeout} = gen_udp:recv(ServerUdpSocket, 0, ?SmallTimeoutMilliSec).


networkacl_allowed_work(_Config) ->
    {ok, Socket} = do_handshake_userpass(),
    {ok, success} = do_auth(Socket, ?Username, ?Password),

     % request UDP ASSOCIATE
    ok = gen_tcp:send(Socket, <<5, ?CMD_UDP_ASSOCIATE, ?RSV, ?ATYP_IPV4, 0,0,0,0, 0,0>>),
    {ok, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, IfAddrBytes:4/binary, PortBytes:2/binary>>} = gen_tcp:recv(Socket, 0, ?TimeoutMilliSec),
    
    % create two udp sockets - first to act as the socks client, second as the destination host
    {ok, ClientUdpSocket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:connect(ClientUdpSocket, helpers:bytes_to_addr(IfAddrBytes), binary:decode_unsigned(PortBytes)),

    {ok, ServerUdpSocket} = gen_udp:open(0, [binary, {active, false}]), % server listens on allowed address
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