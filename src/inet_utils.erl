-module(inet_utils).

-export([inet_aton/1]).
-export([ip_between/3]).

%% @doc Converts tuple with a human readable ip
%% address representation into an uint32.
-spec inet_aton(tuple) -> pos_integer().
inet_aton(Ip) ->
    case Ip of
        {O1Bin, O2Bin, O3Bin, O4Bin} ->
            % ipv4
            B1 = O1Bin bsl 24,
            B2 = O2Bin bsl 16,
            B3 = O3Bin bsl 8,
            B4 = O4Bin,
            B1 + B2 + B3 + B4;
        {O1Bin, O2Bin, O3Bin, O4Bin, O5Bin, O6Bin, O7Bin, O8Bin} ->
            % ipv6
            B1 = O1Bin bsl 112,
            B2 = O2Bin bsl 96,
            B3 = O3Bin bsl 80,
            B4 = O4Bin bsl 64,
            B5 = O5Bin bsl 48,
            B6 = O6Bin bsl 32,
            B7 = O7Bin bsl 16,
            B8 = O8Bin,
            B1 + B2 + B3 + B4 + B5 + B6 + B7 + B8
    end.

%% @doc Checks if the given IP address falls into the given network
%% range. E.g: ip_between({192,168,0,10}, {192.168.0.0}, 24).
-spec ip_between(tuple, tuple, pos_integer()) -> boolean().
ip_between(Ip, Network, NetworkBits) ->
    IpNum = inet_aton(Ip),
    BitsHosts = case tuple_size(Ip) of
        4 -> 32 - NetworkBits;
        8 -> 128 - NetworkBits
    end,

    NetLow = inet_aton(Network) bsr BitsHosts bsl BitsHosts,
    NetHigh = NetLow + erlang:trunc(math:pow(2, BitsHosts)) - 1,
    IpNum >= NetLow andalso IpNum =< NetHigh.

