-module(helpers).
-include("socks5.hrl").

-export([bytes_to_addr/1, addr_to_bytes/1, integer_to_2byte_binary/1, bytes_to_atyp/1, resolve/1]).

% convert bytes into tuple representation of IP address (tuple)
bytes_to_addr(Bytes) ->
    case byte_size(Bytes) of
        4 ->
            A = binary:bin_to_list(Bytes),
            list_to_tuple(A);
        16 ->
            bytes_to_ipv6_addr(Bytes)
    end.

addr_to_bytes(Addr) ->
    binary:list_to_bin(tuple_to_list(Addr)).

bytes_to_ipv6_addr(Bytes) ->
    bytes_to_ipv6_addr([], Bytes).
bytes_to_ipv6_addr(Acc, <<H:2/binary, T/binary>>) ->
    bytes_to_ipv6_addr(Acc ++ [binary:decode_unsigned(H)], T);
bytes_to_ipv6_addr(Acc, <<>>) ->
    list_to_tuple(Acc).

% convert integer to 2-byte unsigned binary
integer_to_2byte_binary(Integer) ->
    Bytes = binary:encode_unsigned(Integer),
    case byte_size(Bytes) of
        1 ->
            <<0, Bytes/binary>>;
        2 ->
            Bytes
    end.


% figre address type by bytes
bytes_to_atyp(Bytes) ->
    case byte_size(Bytes) of
        4 ->
            ?ATYP_IPV4;
        8 ->
            ?ATYP_IPV6;
        _ ->
            ?ATYP_DOMAINNAME
    end.


% resolve domain
resolve(Domain) ->
    {ok,{hostent,_,_,_,_,[Addr|_]}} = inet:gethostbyname(Domain), % resolve name to ipv4/ipv6 address
    Addr.