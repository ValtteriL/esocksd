-module(config).

-export([load/1, auth_required/0, command_allowed/1, address_allowed/1, auth_credentials_correct/2, listen_addresses/0]).

% load configuration from filename
load(Filename) ->
    asd.

% check if authentication required by config
auth_required() ->
    false.

% check if SOCKS command allowed by config
command_allowed(Command) ->
    false.

% check if address allowed to be connected to by config
address_allowed(Address) ->
    false.

% check if username and password combination is correct
auth_credentials_correct(Username, Password) ->
    false.

% get all address and port combinations the SOCKS server should listen on
listen_addresses() ->
    [].