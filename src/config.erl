-module(config).

-export([load/1, auth_required/0, command_allowed/1, address_allowed/1, auth_credentials_correct/2, listen_addresses/0]).

-define(LOG_LEVELS, [emergency, alert, critical, error, warning, notice, info, debug]).
-define(AUTH_METHODS, [userpass, none]).
-define(COMMANDS, [connect, bind, udp_associate]).

% default config values
-define(DEFAULT_VALUES, [
    {listenaddress, ["0.0.0.0", "::"]}, 
    {port, ["1080"]}, 
    {loglevel, ["notice"]}, 
    {logfile, ["esocksd.log"]}, 
    {authmethod, ["none"]},
    {allowcommands, ["connect", "bind", "udp_associate"]}, 
    {allownetwork, ["0.0.0.0/0", "::/0"]}, 
    {disallownetwork, []}
]).



% load configuration from filename
load(Filename) ->
    
    % create ETS table for config
    ets:new(?MODULE, [bag, named_table]),

    % read file into list
    {ok, Content} = file:read_file(Filename),
    Parts = binary:split(Content, [<<"\n">>], [trim_all, global]),

    % discard comments and empty lines 
    Configlines = lists:filter(fun(X) -> 
        (re:run(X, "^#") ==  nomatch) and
        (re:run(X, "^\\h*$") == nomatch)
    end, 
    Parts),

    % store config to ETS
    lists:foreach(fun(Line) ->
        case re:split(Line, "\\h+", [trim, {return, list}]) of
            ["ListenAddress", Rest] -> 
                store_listenaddress(Rest);
            ["Port", Rest] -> 
                store_port(Rest);
            ["LogLevel", Rest] -> 
                store_loglevel(Rest);
            ["LogFile", Rest] ->
                true = ets:insert(?MODULE, {logfile, Rest});
            ["AuthMethod", Rest] -> 
                store_authmethod(Rest);
            ["AuthFile", Rest] -> 
                true = ets:insert(?MODULE, {authfile, Rest});
            ["AllowCommands"|Rest] ->
                store_allowcommands(Rest);
            ["AllowNetwork", Rest] -> 
                store_allownetwork(Rest);
            ["DisallowNetwork", Rest] -> 
                store_disallownetwork(Rest)
        end
    end, 
    Configlines),

    % set default values for unset parameters
    load_default_config(),

    % set logging settings
    [{loglevel, LogLevel}] = ets:lookup(?MODULE, loglevel),
    [{logfile, LogFile}] = ets:lookup(?MODULE, logfile),
    Config = #{config => #{file => LogFile}, level => LogLevel},
    logger:add_handler(myhandler, logger_std_h, Config),

    % if auth required and auth file set, load credentials
    case (auth_required()) and (ets:member(?MODULE, authfile)) of
        true -> 
            [{authfile, AuthFile}] = ets:member(?MODULE, authfile),
            load_credentials(AuthFile);
        _ -> ok
    end,

    ok.

% check if authentication required by config
auth_required() ->
    %TODO
    false.

% check if SOCKS command allowed by config
command_allowed(Command) ->
    %TODO
    false.

% check if address allowed to be connected to by config
address_allowed(Address) ->
    %TODO
    false.

% check if username and password combination is correct
auth_credentials_correct(Username, Password) ->
    %TODO
    false.

% get all address and port combinations the SOCKS server should listen on
listen_addresses() ->
    %TODO
    [].


%%% helpers

% {listenaddress, Listenaddress} - multiple
store_listenaddress(ListenAddress) ->
    % ListenAddress IPv4_addr|IPv6_addr
    {ok, IPAddress} = inet:parse_address(ListenAddress),
    true = ets:insert(?MODULE, {listenaddress, IPAddress}).

% {port, Port} - multiple
store_port(Port) ->
    IntPort = list_to_integer(Port),
    true = ets:insert(?MODULE, {port, IntPort}).

% {loglevel, LogLevel}
store_loglevel(LogLevel) ->
    % verify allowed value
    LogLevelAtom = list_to_atom(LogLevel),
    true = lists:member(LogLevelAtom, ?LOG_LEVELS),
    true = ets:insert(?MODULE, {loglevel, LogLevelAtom}).

% {authmethod, AuthMethod}
store_authmethod(AuthMethod) ->
    % verify allowed value
    AuthMethodAtom = list_to_atom(AuthMethod),
    true = lists:member(AuthMethodAtom, ?AUTH_METHODS),
    true = ets:insert(?MODULE, {authmethod, AuthMethodAtom}).

% {allowcommands, Command} - multiple
store_allowcommands(AllowCommands) ->
    % verify allowed value for each
    lists:foreach(fun(Elem) -> 
        AllowCommandAtom = list_to_atom(Elem),
        true = lists:member(AllowCommandAtom, ?COMMANDS),
        true = ets:insert(?MODULE, {allowcommands, AllowCommandAtom})
        end, 
    AllowCommands).


store_network(Network, AllowDisallow) ->
    [Address, FixedBits] = string:split(Network, "/"),
    {ok, AddrTuple} = inet:parse_address(Address),
    FixedBitsInt = list_to_integer(FixedBits),
    
    case tuple_size(AddrTuple) of
        4 ->
            % ipv4
            true = (FixedBitsInt >= 0) and (FixedBitsInt =< 32),
            true = ets:insert({AllowDisallow, inet, AddrTuple, FixedBitsInt}),
            ok;
        8 ->
            % ipv6
            true = (FixedBitsInt >= 0) and (FixedBitsInt =< 128),
            true = ets:insert({AllowDisallow, inet6, AddrTuple, FixedBitsInt}),
            ok
    end.


% {network, allow, inet|inet6, IpTuple, NetworkBits} - multiple
store_allownetwork(Network) ->
   store_network(Network, allownetwork).

% {network, block, inet|inet6, IpTuple, NetworkBits} - multiple
store_disallownetwork(Network) ->
   store_network(Network, disallownetwork).



% fill unset config values
load_default_config() ->
    lists:foreach(fun({Param, ValueList}) ->
        case ets:member(?MODULE, Param) of
            false ->
                % param not set, set default value
                lists:foreach(fun(Value) -> set_config(Param, Value) end, ValueList);
            _ ->
                ok
            end
        end,
    ?DEFAULT_VALUES).


% store value for parameter
set_config(Param, Value) ->
    case Param of
        listenaddress -> store_listenaddress(Value);
        port -> store_port(Value);
        loglevel -> store_loglevel(Value);
        logfile -> true = ets:insert(?MODULE, {logfile, Value});
        authmethod -> store_authmethod(Value);
        allowcommands -> store_allowcommands(Value);
        allownetwork -> store_allownetwork(Value);
        disallownetwork -> store_disallownetwork(Value)
    end.


% load credentials from authfile
% expects credentials to be in format 
%   username:password
% {userpass, Username, Password} - multiple
load_credentials(AuthFile) ->

    {ok, Content} = file:read_file(AuthFile),
    Parts = binary:split(Content, [<<"\n">>], [trim_all, global]),

    % discard comments and empty lines 
    Credlines = lists:filter(fun(X) -> 
        (re:run(X, "^#") ==  nomatch) and
        (re:run(X, "^\\h*$") == nomatch)
    end, 
    Parts),

    % store creds to ets
    lists:foreach(fun(Credline) ->  
        [Username, Password] = re:split(Credline, ":", [trim, {return, list}]),
        ets:insert({userpass, Username, Password})
    end, Credlines),

    ok.