-module(config).

-export([load/0, auth_required/0, command_allowed/1, address_allowed/1, auth_credentials_correct/2, listen_addresses/0]).

-define(LOG_LEVELS, [emergency, alert, critical, error, warning, notice, info, debug]).
-define(AUTH_METHODS, [userpass, none]).
-define(COMMANDS, [connect, bind, udp_associate]).


-define(DEFAULT_LISTENADDRESS, ["0.0.0.0", "::"]).
-define(DEFAULT_PORT, [1080]).
-define(DEFAULT_LOGLEVEL, notice).
-define(DEFAULT_LOGFILE, "esocksd.log").
-define(DEFAULT_AUTHMETHOD, none).
-define(DEFAULT_ALLOWCOMMANDS, [connect, bind, udp_associate]).
-define(DEFAULT_NETWORKACL, [
    {allow, "0.0.0.0/0"}
]).
-define(DEFAULT_NETWORKACL_6, [
    {allow, "::/0"}
]).
-define(DEFAULT_USERPASS, []).


-define(CONFIG_COMMANDS, [listenaddress, port, loglevel, logfile, authmethod, userpass, allowcommands, networkacl, networkacl6]).

% load configuration
-spec load() -> ok.
load() ->
    
    % use default config for unset values
    set_env_if_unset(listenaddress, ?DEFAULT_LISTENADDRESS),
    set_env_if_unset(port, ?DEFAULT_PORT),
    set_env_if_unset(loglevel, ?DEFAULT_LOGLEVEL),
    set_env_if_unset(logfile, ?DEFAULT_LOGFILE),
    set_env_if_unset(authmethod, ?DEFAULT_AUTHMETHOD),
    set_env_if_unset(userpass, ?DEFAULT_USERPASS),
    set_env_if_unset(allowcommands, ?DEFAULT_ALLOWCOMMANDS),
    set_env_if_unset(networkacl, ?DEFAULT_NETWORKACL),
    set_env_if_unset(networkacl6, ?DEFAULT_NETWORKACL_6),

    % store config to ETS
    ets:new(?MODULE, [named_table, set]),
    lists:foreach(fun(CMD) -> store_ets(CMD) end, ?CONFIG_COMMANDS),

    % set logging settings
    LogLevel = lookup_ets(loglevel),
    LogFile = lookup_ets(logfile),
    logger:set_primary_config(level, LogLevel), % set loglevel globally
    Config = #{config => #{file => LogFile}, level => LogLevel},
    logger:add_handler(myhandler, logger_std_h, Config),

    ok.


set_env_if_unset(Key, Value) ->
    case application:get_env(esocksd, Key) of
        undefined -> application:set_env([{esocksd, [{Key, Value}]}]);
        _ -> ok
    end.

store_ets(Key) -> 
    {ok, Value} = application:get_env(esocksd, Key),
    true = ets:insert(?MODULE, {Key, Value}).

lookup_ets(Key) ->
    [{Key, Value}] = ets:lookup(?MODULE, Key),
    Value.


% check if authentication required by config
-spec auth_required() -> boolean().
auth_required() ->
    userpass == lookup_ets(authmethod).

% check if SOCKS command allowed by config
-spec command_allowed(atom()) -> boolean().
command_allowed(Command) ->
    AllowedCommands = lookup_ets(allowcommands),
    lists:member(Command, AllowedCommands).

% check if address allowed to be connected to by config
-spec address_allowed(tuple()) -> boolean().
address_allowed(Address) ->
    ACL = case tuple_size(Address) of
        4 -> lookup_ets(networkacl);
        8 -> lookup_ets(networkacl6)
    end,

    % go through rules one by one and see
    % if they allow or disallow accessing the Address
    Judgement = lists:foldl(
        fun({Type, CIDR}, Acc) -> 
            case Acc of
                notset ->
                    % Acc not yet set
                    % check if current rule catches it
                    {Network, NetworkBits} = cidr_to_addr_and_fixedbits(CIDR),
                    case {Type, inet_utils:ip_between(Address, Network, NetworkBits)} of
                        {allow, true} -> true; % allow
                        {block, true} -> false; % disallow
                        _ -> notset % not caught by this rule
                    end;
                _ ->
                    Acc % Acc has been set by previous rule
            end
    end,
    notset, ACL),

    % return the value decided by rules
    case Judgement of
        notset -> false; % by default, disallow access if config does not allow explicitly
        _ -> Judgement
    end.

% check if username and password combination is correct
-spec auth_credentials_correct(string(), string()) -> boolean().
auth_credentials_correct(Username, Password) ->
    UserList = lookup_ets(userpass),
    lists:member({Username, Password}, UserList).

% get all address and port combinations the SOCKS server should listen on
-type listen_addr_list() :: [{tuple(), integer()}].
-spec listen_addresses() -> listen_addr_list().
listen_addresses() ->
    ListenAddresses = lookup_ets(listenaddress),
    Ports = lookup_ets(port),

    % generate list of {ListenAddress, Port}
    lists:flatmap(fun(Addr) -> 
        lists:map(fun(Port) ->
            {ok, AddrTuple} = inet:parse_address(Addr),
            {AddrTuple, Port}
        end, Ports)
        end, 
    ListenAddresses).


%%% helpers

% convert cidr to {Address, Fixedbits}
cidr_to_addr_and_fixedbits(CIDR) ->
    [Address, FixedBits] = string:split(CIDR, "/"),
    {ok, AddrTuple} = inet:parse_address(Address),
    FixedBitsInt = list_to_integer(FixedBits),
    
    case tuple_size(AddrTuple) of
        4 -> true = (FixedBitsInt >= 0) and (FixedBitsInt =< 32); % ipv4
        8 -> true = (FixedBitsInt >= 0) and (FixedBitsInt =< 128) % ipv6
    end,

    {AddrTuple, FixedBitsInt}.

