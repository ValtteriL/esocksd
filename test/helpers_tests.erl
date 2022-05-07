-module(helpers_tests).
-include_lib("eunit/include/eunit.hrl").


%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% TESTS DESCRIPTIONS %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%

bytes_to_addr_test_() ->
    [bytes_to_addr_ipv4(), bytes_to_addr_ipv6(), bytes_to_addr_err()].

addr_to_bytes_test_() ->
    [addr_to_bytes_ipv4(), addr_to_bytes_ipv6(), addr_to_bytes_err()].

integer_to_2byte_binary_test_() ->
    [integer_to_2byte_binary()].

%%%%%%%%%%%%%%%%%%%%%%%
%%% SETUP FUNCTIONS %%%
%%%%%%%%%%%%%%%%%%%%%%%
 
%%%%%%%%%%%%%%%%%%%%
%%% ACTUAL TESTS %%%
%%%%%%%%%%%%%%%%%%%%

bytes_to_addr_ipv4() ->
    [?_assertEqual({127,0,0,1}, helpers:bytes_to_addr(<<127,0,0,1>>)),
     ?_assertEqual({10,0,0,1}, helpers:bytes_to_addr(<<10,0,0,1>>)),
     ?_assertEqual({192,168,0,1}, helpers:bytes_to_addr(<<192,168,0,1>>)),
     ?_assertEqual({172,16,0,1}, helpers:bytes_to_addr(<<172,16,0,1>>)),
     
     ?_assertNotEqual({127,0,1,1}, helpers:bytes_to_addr(<<127,0,0,1>>)),
     ?_assertNotEqual({10,0,1,1}, helpers:bytes_to_addr(<<10,0,0,1>>)),
     ?_assertNotEqual({192,168,1,1}, helpers:bytes_to_addr(<<192,168,0,1>>)),
     ?_assertNotEqual({172,16,1,1}, helpers:bytes_to_addr(<<172,16,0,1>>))].

bytes_to_addr_ipv6() ->
    [?_assertEqual({0,0,0,0,0,0,0,0}, helpers:bytes_to_addr(<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>)),
     ?_assertEqual({0,0,0,0,0,0,0,1}, helpers:bytes_to_addr(<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1>>)),
     ?_assertEqual({0,0,0,0,0,0,1,1}, helpers:bytes_to_addr(<<0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1>>)),
     ?_assertEqual({1,0,0,0,0,0,0,0}, helpers:bytes_to_addr(<<0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>)),
     
     ?_assertNotEqual({0,0,0,0,0,0,0,1}, helpers:bytes_to_addr(<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>)),
     ?_assertNotEqual({0,0,0,0,0,0,1,1}, helpers:bytes_to_addr(<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1>>)),
     ?_assertNotEqual({0,0,0,0,0,1,1,1}, helpers:bytes_to_addr(<<0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1>>)),
     ?_assertNotEqual({1,0,0,0,1,1,1,1}, helpers:bytes_to_addr(<<0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>))].

bytes_to_addr_err() ->
    [?_assertError({case_clause,_}, helpers:bytes_to_addr(<<1>>)),
     ?_assertError({case_clause,_}, helpers:bytes_to_addr(<<1,2,3,4,5>>)),
     ?_assertError({case_clause,_}, helpers:bytes_to_addr(<<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17>>)),
     ?_assertError(badarg, helpers:bytes_to_addr(123)),
     ?_assertError(badarg, helpers:bytes_to_addr("asd")),
     ?_assertError(badarg, helpers:bytes_to_addr([1,2,3,4]))].

addr_to_bytes_ipv4() ->
    [?_assertEqual(<<127,0,0,1>>, helpers:addr_to_bytes({127,0,0,1})),
     ?_assertEqual(<<10,0,0,1>>, helpers:addr_to_bytes({10,0,0,1})),
     ?_assertEqual(<<192,168,0,1>>, helpers:addr_to_bytes({192,168,0,1})),
     ?_assertEqual(<<172,16,0,1>>, helpers:addr_to_bytes({172,16,0,1})),

     ?_assertNotEqual(<<127,0,1,1>>, helpers:addr_to_bytes({127,0,0,1})),
     ?_assertNotEqual(<<10,0,1,1>>, helpers:addr_to_bytes({10,0,0,1})),
     ?_assertNotEqual(<<192,168,1,1>>, helpers:addr_to_bytes({192,168,0,1})),
     ?_assertNotEqual(<<172,16,1,1>>, helpers:addr_to_bytes({172,16,0,1}))].

addr_to_bytes_ipv6() ->
    [?_assertEqual(<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>, helpers:addr_to_bytes({0,0,0,0,0,0,0,0})),
     ?_assertEqual(<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1>>, helpers:addr_to_bytes({0,0,0,0,0,0,0,1})),
     ?_assertEqual(<<0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0>>, helpers:addr_to_bytes({0,0,0,0,0,0,1,0})),
     ?_assertEqual(<<0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>, helpers:addr_to_bytes({1,0,0,0,0,0,0,0})),

     ?_assertNotEqual(<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1>>, helpers:addr_to_bytes({0,0,0,0,0,0,0,0})),
     ?_assertNotEqual(<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1>>, helpers:addr_to_bytes({0,0,0,0,0,0,0,1})),
     ?_assertNotEqual(<<0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0>>, helpers:addr_to_bytes({0,0,0,0,0,0,1,0})),
     ?_assertNotEqual(<<0,1,0,0,0,0,0,0,0,0,0,0,0,0,1,0>>, helpers:addr_to_bytes({1,0,0,0,0,0,0,0}))].

addr_to_bytes_err() -> 
    [?_assertError(function_clause, helpers:addr_to_bytes({1})),
     ?_assertError(function_clause, helpers:addr_to_bytes({1,2,3,4,5})),
     ?_assertError(function_clause, helpers:addr_to_bytes({1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17})),
     ?_assertError(function_clause, helpers:addr_to_bytes(123)),
     ?_assertError(function_clause, helpers:addr_to_bytes("asd")),
     ?_assertError(function_clause, helpers:addr_to_bytes([1,2,3,4]))].

integer_to_2byte_binary() -> 
    [?_assertEqual(<<0,1>>, helpers:integer_to_2byte_binary(1)),
     ?_assertEqual(<<0,255>>, helpers:integer_to_2byte_binary(255)),
     ?_assertEqual(<<1,0>>, helpers:integer_to_2byte_binary(256)),
     ?_assertEqual(<<255,255>>, helpers:integer_to_2byte_binary(65535))].


%%%%%%%%%%%%%%%%%%%%%%%%
%%% HELPER FUNCTIONS %%%
%%%%%%%%%%%%%%%%%%%%%%%%