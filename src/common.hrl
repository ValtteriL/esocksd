-record(stage,{
    handshake, % nothing exchanged yet - do handshake
    authenticate, % handshake done and auth required - do authentication
    request, % handshake (and auth) done - receive SOCKS request
    connect, % CONNECT or BIND in place and connected - relay TCP traffic
    udp_associate % UDP ASSOCIATE in place - relay UDP traffic
}).
-record(state, {socket, connectSocket, connectSocketIpv6, stage = #stage.handshake, udpClientIP, udpClientPort}).