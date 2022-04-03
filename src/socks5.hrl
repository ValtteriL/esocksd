% defined values for METHOD
-define(M_NOAUTH , 0). % NO AUTHENTICATION REQUIRED
-define(M_GSSAPI , 1).
-define(M_USERPASS , 2).
-define(SUPPORTED_VERSIONS , [5]).
-define(SUPPORTED_METHODS, [?M_NOAUTH]).

-define(M_NOTAVAILABLE , 255). % NO ACCEPTABLE METHODS
-define(RSV, 0). % Reserved
-define(UDP_RSV, <<0,0>>). % Reserved
-define(UDP_FRAG, 0).

-define(ATYP_IPV4, 1). % IP V4 address '01'
-define(ATYP_IPV6, 4). % IP V6 address '04'
-define(ATYP_DOMAINNAME, 3). % DOMAINNAME '03'

-define(CMD_CONNECT, 1).  % CONNECT '01'
-define(CMD_BIND, 2).  % BIND '02'
-define(CMD_UDP_ASSOCIATE, 3).  % UDP ASSOCIATE '03'

-define(REP_SUCCESS, 0).
-define(REP_GEN_FAILURE, 1).
-define(REP_CONNECTION_NOT_ALLOWED, 2).
-define(REP_NETWORK_UNREACHABLE, 3).
-define(REP_HOST_UNREACHABLE, 4).
-define(REP_CONN_REFUSED, 5).
-define(REP_TTL_EXPIRED, 6).
-define(REP_CMD_NOT_SUPPORTED, 7).
-define(REP_ATYPE_NOT_SUPPORTED, 8).

-define(REP_PADDING, <<?ATYP_IPV4, 0,0,0,0,0,0>>). % padding for replies where addr and port irrelevant 

-define(HOST_ALLIFACES, <<0,0,0,0>>).
-define(HOST_NOPORTS, <<0,0>>).


-record(stage,{
    handshake, % nothing exchanged yet - do handshake
    authenticate, % handshake done and auth required - do authentication
    request, % handshake (and auth) done - receive SOCKS request
    connect, % CONNECT or BIND in place and connected - relay TCP traffic
    udp_associate % UDP ASSOCIATE in place - relay UDP traffic
}).
-record(state, {socket, connectSocket, connectSocketIpv6, stage = #stage.handshake, udpClientIP, udpClientPort}).