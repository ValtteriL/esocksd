-module(socks4).
-include("socks4.hrl").
-include("common.hrl").

-export([negotiate/2]).

% SOCKS4 + SOCKS4A  related functions
% followed documents: 
% - https://www.openssh.com/txt/socks4.protocol
% - https://www.openssh.com/txt/socks4a.protocol


negotiate(Msg, State) ->
    
    <<4, CD, DSTPORT:2/binary, DSTIP:4/binary, Rest/binary>> = Msg,
    0 = binary:last(Rest),

    case CD of
        ?CD_CONNECT ->
            connect(DSTIP, DSTPORT, State);
        ?CD_BIND ->
            bind(DSTIP, State)
    end.



% handle CONNECT command
% connects to a remote host
% stores the socket to connectSocket in state
% then relay traffic between socket and connectSocket
connect(DST_ADDR, DST_PORT, State) ->
    case  gen_tcp:connect(DST_ADDR, DST_PORT, [{active, once}], 5000) of
        {ok, ConnectSocket} ->
            logger:debug("Worker (in CONNECT): Connection established to remote host!"),
            
            % communicate the bound hostname and port
            gen_tcp:send(State#state.socket, <<4, ?REQ_GRANTED, DST_PORT, DST_ADDR>>),
            
            {noreply, State#state{stage=#stage.connect, connectSocket=ConnectSocket}};
        {error, Reason} ->
            logger:debug("Worker (in CONNECT): failed to connect to remote host: ~p", [Reason]),
            gen_tcp:send(State#state.socket, <<4, ?REQ_REJECTED_OR_FAILED, DST_PORT, DST_ADDR>>),
            gen_tcp:shutdown(State#state.socket, write),
            {stop, normal, State}
    end.

% handle BIND command
% starts listening for TCP connections
% stores the listening socket to connectSocket
% once connection received relay traffic between socket and connectSocket
bind(DST_ADDR, State) ->
    % bind socket on random tcp port
    {ok, ListenSocket} = gen_tcp:listen(0, []),
    {ok, {IfAddr, Port}} = inet:sockname(ListenSocket),

    logger:debug("Worker (in BIND): Listening for connections on port ~B...~n", [Port]),

    PortBytes = helpers:integer_to_2byte_binary(Port),
    IfAddrBytes = helpers:addr_to_bytes(IfAddr),

    % communicate the bound hostname and port
    gen_tcp:send(State#state.socket, <<4, ?REQ_GRANTED, PortBytes/binary, IfAddrBytes/binary>>),

    % wait for connection to the socket
    case gen_tcp:accept(ListenSocket, 60*1000*2) of
        {ok, Socket} ->

            % convert received data to Erlang messages
            ok = inet:setopts(Socket, [{active, once}]),

            % get peer info
            {ok,{RemoteAddr,RemotePort}} = inet:peername(Socket),
            RemoteAddrBytes = helpers:addr_to_bytes(RemoteAddr),
            RemotePortBytes = helpers:integer_to_2byte_binary(RemotePort),

            logger:info("Worker (in BIND): Connection received from ~p:~B!", [RemoteAddr, RemotePort]),

            % The SOCKS server checks the IP address of the originating host against
            % the value of DSTIP specified in the client's BIND request.  If a mismatch
            % is found, the CD field in the second reply is set to 91 and the SOCKS
            % server closes both connections.  If the two match, CD in the second
            % reply is set to 90 and the SOCKS server gets ready to relay the traffic
            % on its two connections. From then on the client does I/O on its connection
            % to the SOCKS server as if it were directly connected to the application
            % server.

            case RemoteAddr of
                DST_ADDR ->
                    gen_tcp:send(State#state.socket, <<4, ?REQ_GRANTED, RemoteAddrBytes/binary, RemotePortBytes/binary>>);
                _ ->
                    logger:debug("Worker (in BIND): Connection received from wrong host"),
                    gen_tcp:send(State#state.socket, <<4, ?REQ_REJECTED_OR_FAILED, RemoteAddrBytes/binary, RemotePortBytes/binary>>),
                    gen_tcp:shutdown(State#state.socket, write),
                    gen_tcp:close(ListenSocket)
            end,

            {noreply, State#state{stage=#stage.connect, connectSocket=Socket}};
        {error, _} ->

            logger:info("Worker (in BIND): Error accepting connection"),

            % communicate error
            gen_tcp:send(State#state.socket, <<4, ?REQ_REJECTED_OR_FAILED, 0,0,0,0, 0,0>>),
            gen_tcp:shutdown(State#state.socket, write),
            gen_tcp:close(ListenSocket),
            {stop, normal, State}
    end.
