-export_type([stage/0, state/0]).

-record(stage,{
    handshake, % nothing exchanged yet - do handshake
    authenticate, % handshake done and auth required - do authentication
    request, % handshake (and auth) done - receive SOCKS request
    connect, % CONNECT or BIND in place and connected - relay TCP traffic
    udp_associate % UDP ASSOCIATE in place - relay UDP traffic
}).

-record(state, {
    workerId :: integer() | undefined,
    supervisor :: pid() | undefined,
    socket :: inet:socket() | undefined,
    connectSocket :: inet:socket() | undefined,
    connectSocketIpv6 :: inet:socket() | undefined,
    stage = #stage.handshake,
    udpClientIP :: tuple() | undefined,
    udpClientPort :: integer() | undefined
    }).

-type stage() :: #stage{}.
-type state() :: #state{}.