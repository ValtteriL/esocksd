-module(inet_utils_tests).
-include_lib("eunit/include/eunit.hrl").


%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% TESTS DESCRIPTIONS %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%
 
 ip_between_test_() ->
    [ipv4_between(),
     ipv6_between()].

%%%%%%%%%%%%%%%%%%%%%%%
%%% SETUP FUNCTIONS %%%
%%%%%%%%%%%%%%%%%%%%%%%
 
%%%%%%%%%%%%%%%%%%%%
%%% ACTUAL TESTS %%%
%%%%%%%%%%%%%%%%%%%%

ipv6_between() ->
    [?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {0,0,0,0,0,0,0,1}, 128)),
     ?_assert(inet_utils:ip_between({1,0,0,0,0,0,0,1}, {1,0,0,0,0,0,0,1}, 128)),
     ?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {0,0,0,0,0,0,1,1}, 96)),
     ?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {0,0,0,0,0,0,1,1}, 96)),
     ?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {0,0,0,0,1,1,1,1}, 64)),
     ?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {0,0,0,0,1,1,1,1}, 64)),
     ?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {0,0,1,1,1,1,1,1}, 32)),
     ?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {0,0,1,1,1,1,1,1}, 32)),
     ?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {0,1,1,1,1,1,1,1}, 16)),
     ?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {0,1,1,1,1,1,1,1}, 16)),
     ?_assert(inet_utils:ip_between({1,0,0,0,0,0,0,1}, {1,1,1,1,1,1,1,1}, 8)),
     ?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {0,1,1,1,1,1,1,1}, 8)),
     ?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {1,1,1,1,1,1,1,1}, 0)),
     ?_assert(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {0,1,0,1,0,1,0,1}, 0)),

     ?_assertNot(inet_utils:ip_between({0,0,0,0,0,0,0,2}, {0,0,0,0,0,0,0,1}, 128)),
     ?_assertNot(inet_utils:ip_between({0,0,0,0,0,0,0,1}, {1,0,0,0,0,0,0,1}, 128)),
     ?_assertNot(inet_utils:ip_between({0,0,0,0,0,1,0,0}, {0,0,0,0,0,0,1,1}, 96)),
     ?_assertNot(inet_utils:ip_between({0,0,0,0,1,0,0,0}, {0,0,0,0,0,0,1,1}, 96)),
     ?_assertNot(inet_utils:ip_between({0,0,0,1,0,0,0,0}, {0,0,0,0,1,1,1,1}, 64)),
     ?_assertNot(inet_utils:ip_between({0,0,1,0,0,0,0,0}, {0,0,0,0,1,1,1,1}, 64)),
     ?_assertNot(inet_utils:ip_between({0,1,0,0,0,0,0,0}, {0,0,1,1,1,1,1,1}, 32)),
     ?_assertNot(inet_utils:ip_between({1,0,0,0,0,0,0,0}, {0,0,1,1,1,1,1,1}, 32)),
     ?_assertNot(inet_utils:ip_between({1,0,0,0,0,0,0,0}, {0,1,1,1,1,1,1,1}, 16)),
     ?_assertNot(inet_utils:ip_between({1,1,0,0,0,0,0,0}, {0,1,1,1,1,1,1,1}, 16)),
     ?_assertNot(inet_utils:ip_between({2000,0,0,0,0,0,0,0}, {1,1,1,1,1,1,1,1}, 8)),
     ?_assertNot(inet_utils:ip_between({1024,0,0,0,0,0,0,0}, {0,1,1,1,1,1,1,1}, 8))].

ipv4_between() ->
    [?_assert(inet_utils:ip_between({192,168,0,1}, {192,168,0,1}, 32)),
     ?_assert(inet_utils:ip_between({192,168,0,100}, {192,168,0,100}, 32)),
     ?_assert(inet_utils:ip_between({192,168,0,10}, {192,168,0,0}, 24)),
     ?_assert(inet_utils:ip_between({192,168,0,10}, {192,168,0,100}, 24)),
     ?_assert(inet_utils:ip_between({172,16,0,1}, {172,16,0,0}, 16)),
     ?_assert(inet_utils:ip_between({172,16,100,1}, {172,16,0,100}, 16)),
     ?_assert(inet_utils:ip_between({10,0,0,1}, {10,0,0,0}, 8)),
     ?_assert(inet_utils:ip_between({10,100,0,1}, {10,0,0,100}, 8)),
     ?_assert(inet_utils:ip_between({10,0,0,1}, {10,0,100,0}, 0)),
     ?_assert(inet_utils:ip_between({10,100,0,1}, {10,0,0,0}, 0)),

     ?_assertNot(inet_utils:ip_between({192,168,0,2}, {192,168,0,1}, 32)),
     ?_assertNot(inet_utils:ip_between({192,168,1,10}, {192,168,0,0}, 32)),
     ?_assertNot(inet_utils:ip_between({192,168,1,1}, {192,168,0,1}, 24)),
     ?_assertNot(inet_utils:ip_between({192,169,0,10}, {192,168,0,0}, 24)),
     ?_assertNot(inet_utils:ip_between({172,17,0,10}, {172,16,0,0}, 16)),
     ?_assertNot(inet_utils:ip_between({175,16,0,10}, {172,16,0,0}, 16)),
     ?_assertNot(inet_utils:ip_between({11,0,0,10}, {10,0,51,0}, 8)),
     ?_assertNot(inet_utils:ip_between({10,0,0,10}, {20,0,0,0}, 8))].


%%%%%%%%%%%%%%%%%%%%%%%%
%%% HELPER FUNCTIONS %%%
%%%%%%%%%%%%%%%%%%%%%%%%