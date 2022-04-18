-module(socks_config_SUITE).
-include_lib("common_test/include/ct.hrl").
-include("src/socks5.hrl").

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
    networkacl_disallowed_fail_connect_socks4/1, networkacl_disallowed_fail_connect_socks5/1, 
    networkacl_disallowed_fail_udp_associate_socks4/1, networkacl_disallowed_fail_udp_associate_socks5/1, 
    networkacl_allowed_work_socks4/1, networkacl_allowed_work_socks5/1]).
 
all() -> [listenaddress_port_logfile, 
    authmethod_userpass_socks4_disabled, authmethod_userpass_correct_creds_work, authmethod_userpass_incorrect_creds_fail,
    allowed_commands_work, disallowed_commands_fail, 
    networkacl_disallowed_fail_connect_socks4, networkacl_disallowed_fail_connect_socks5, 
    networkacl_disallowed_fail_udp_associate_socks4, networkacl_disallowed_fail_udp_associate_socks5, 
    networkacl_allowed_work_socks4, networkacl_allowed_work_socks5].
 
-define(TimeoutMilliSec, 10*1000).
-define(HandshakeNoAuth, <<5, 1, ?M_NOAUTH>>).
-define(ReplySuccessIpv4, <<5, ?REP_SUCCESS, ?RSV, ?ATYP_IPV4, _Rest/binary>>).


% start service
init_per_suite(Config) ->

    % config for application in tests
    ConfigEnv = [
        {listenaddress, ["0.0.0.0", "::"]}, 
        {port, [1080]}, 
        {loglevel, debug}, 
        {logfile, "esocksd.log"}, 
        {authmethod, none},
        {allowcommands, [connect, bind, udp_associate]},
        {networkacl, [
            {allow, "0.0.0.0/0"},
            {block, "255.255.255.255/31"}
        ]},
        {networkacl6, [
            {allow, "::/0"}
        ]},
        {userpass, [
            {"username", "password"},
            {"admin", "secret"}
        ]}
    ],

    % start esocksd with the config
    ok = application:set_env([{esocksd, ConfigEnv}], []),
    ok = application:start(esocksd),

    EchoPort = test_helpers:spawn_echoserver(), % spawn echo server for tests
    [{echoport, EchoPort}| Config].

% stop service
end_per_suite(Config) ->
    ok = application:stop(esocksd),
    Config.


%%%%%%%%
%
% listtenaddr, port, logfile
%
%%%%%%%%

listenaddress_port_logfile(_Config) -> ok.


%%%%%%%%
%
% authmethod
%
%%%%%%%%

authmethod_userpass_socks4_disabled(_Config) -> ok.
authmethod_userpass_correct_creds_work(_Config) -> ok.
authmethod_userpass_incorrect_creds_fail(_Config) -> ok.

%%%%%%%%
%
% allowing/disallowing commands
%
%%%%%%%%

allowed_commands_work(_Config) -> ok.
disallowed_commands_fail(_Config) -> ok.

%%%%%%%%
%
% Network ACL
%
%%%%%%%%

networkacl_disallowed_fail_connect_socks4(_Config) -> ok.
networkacl_disallowed_fail_connect_socks5(_Config) -> ok.
networkacl_disallowed_fail_udp_associate_socks4(_Config) -> ok.
networkacl_disallowed_fail_udp_associate_socks5(_Config) -> ok.
networkacl_allowed_work_socks4(_Config) -> ok.
networkacl_allowed_work_socks5(_Config) -> ok.