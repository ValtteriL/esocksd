-module(config).

-export([load/1, auth_required/0, command_allowed/1, address_allowed/1, auth_credentials_correct/2, listen_addresses/0]).

% load configuration from filename
load(Filename) ->
    
    % create ETS table for config
    ets:new(?MODULE, [set, named_table]),

    % read file into list
    {ok, Content} = file:read_file(Filename),
    Parts = binary:split(Content, [<<"\n">>], [trim_all, global]),

    % discard comments and empty lines 
    Configlines = lists:filter(fun(X) -> 
        (re:run(X, "^#") ==  nomatch) and
        (re:run(X, "^\\h*$") == nomatch)
    end, 
    Parts),

    % TODO: store config to ETS
    lists:foreach(fun(Line) ->
        case re:run(Line, "\\h", [trim]) of
            ["ListenAddress"|Rest] -> ok;
            ["Port"|Rest] -> ok;
            ["LogLevel"|Rest] -> ok;
            ["LogFile"|Rest] -> ok;
            ["AuthMethod"|Rest] -> ok;
            ["AuthFile"|Rest] -> ok;
            ["AllowCommands"|Rest] -> ok;
            ["AllowNetwork"|Rest] -> ok;
            ["DisallowNetwork"|Rest] -> ok
        end
    end, 
    Configlines),

    ok.

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


%%% helpers


