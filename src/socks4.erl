-module(socks4).
-include("socks4.hrl").
-include("common.hrl").

-export([negotiate/2]).

% SOCKS4 + SOCKS4A  related functions
% followed documents: 
% - https://www.openssh.com/txt/socks4.protocol
% - https://www.openssh.com/txt/socks4a.protocol

-spec negotiate(binary(), state()) -> tuple().
negotiate(Msg, State) ->
    
    <<4, CD, DSTPORT:2/binary, DSTIP:4/binary, Rest/binary>> = Msg,
    0 = binary:last(Rest),

    % check for SOCKS4A 
    % A server using protocol 4A must check the DSTIP in the request packet.
    % If it represent address 0.0.0.x with nonzero x, the server must read
    % in the domain name that the client sends in the packet. The server
    % should resolve the domain name and make connection to the destination
    % host if it can. 
    DST_ADDR = case DSTIP of
        <<0,0,0,X>> ->
            % SOCKS4A request
            false = (X == 0),
            [_, Domain, _] = binary:split(Rest, <<0>>, [global]),

            NoticeMsg = io_lib:format("Domain used as DST (~s)", [Domain]),
            socks_worker:log_notice(State#state.workerId, NoticeMsg),
            
            Addr = helpers:resolve(binary_to_list(Domain)), % resolve name to ipv4 address
            Addr;
        _->
            % SOCKS4 request
            helpers:bytes_to_addr(DSTIP)
    end,

    Port = binary:decode_unsigned(DSTPORT),

    Command = case CD of
        ?CD_CONNECT ->
            socks_worker:log_debug(State#state.workerId, "SOCKS4 CONNECT request received"),
            connect;
        ?CD_BIND ->
            socks_worker:log_debug(State#state.workerId, "SOCKS4 BIND request received"),
            bind
    end,

    case {Command, config:command_allowed(Command), config:address_allowed(DST_ADDR)} of
        {connect, true, true} -> connect(DST_ADDR, Port, State);
        {bind, true, true} -> bind(DST_ADDR, State);
        {_, CmdAllowed, AddrAllowed} -> 
            case CmdAllowed of
                false -> socks_worker:log_warning(State#state.workerId, "SOCKS4 command not allowed");
                _ -> ok
            end,
            case AddrAllowed of
                false -> socks_worker:log_warning(State#state.workerId, "Destination address not allowed");
                _ -> ok
            end,
            gen_tcp:send(State#state.socket, <<?REP_VERSION, ?REQ_REJECTED_OR_FAILED, 0,0,0,0, 0,0>>),
            gen_tcp:shutdown(State#state.socket, write),
            gen_tcp:close(State#state.socket),
            {stop, normal, State}
    end.



% handle CONNECT command
% connects to a remote host
% stores the socket to connectSocket in state
% then relay traffic between socket and connectSocket
connect(DST_ADDR, DST_PORT, State) ->

    DbgMsg = io_lib:format("Connecting to ~s:~B", [inet:ntoa(DST_ADDR), DST_PORT]),
    socks_worker:log_debug(State#state.workerId, DbgMsg),

    case gen_tcp:connect(DST_ADDR, DST_PORT, [], 5000) of
        {ok, ConnectSocket} ->

            NoticeMsg = io_lib:format("Connected to ~s:~B", [inet:ntoa(DST_ADDR), DST_PORT]),
            socks_worker:log_notice(State#state.workerId, NoticeMsg),
            
            % communicate the bound hostname and port
            PortBytes = helpers:integer_to_2byte_binary(DST_PORT),
            AddrBytes = helpers:addr_to_bytes(DST_ADDR),

            gen_tcp:send(State#state.socket, <<?REP_VERSION, ?REQ_GRANTED, PortBytes/binary, AddrBytes/binary>>),

            % convert received data to Erlang messages
            ok = inet:setopts(ConnectSocket, [{active, once}]),
            
            {noreply, State#state{stage=#stage.connect, connectSocket=ConnectSocket}};
        {error, Reason} ->
            ErrMsg = io_lib:format("Failed to connect to remote host: ~p", [Reason]),
            socks_worker:log_warning(State#state.workerId, ErrMsg),
            gen_tcp:send(State#state.socket, <<?REP_VERSION, ?REQ_REJECTED_OR_FAILED, DST_PORT/binary, DST_ADDR/binary>>),
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

    StateMsg = io_lib:format("Listening for connections on port ~B...", [Port]),
    socks_worker:log_info(State#state.workerId, StateMsg),

    PortBytes = helpers:integer_to_2byte_binary(Port),
    IfAddrBytes = helpers:addr_to_bytes(IfAddr),

    % communicate the bound hostname and port
    gen_tcp:send(State#state.socket, <<?REP_VERSION, ?REQ_GRANTED, PortBytes/binary, IfAddrBytes/binary>>),

    % wait for connection to the socket
    case gen_tcp:accept(ListenSocket, 60*1000*2) of
        {ok, Socket} ->

            % convert received data to Erlang messages
            ok = inet:setopts(Socket, [{active, once}]),

            % get peer info
            {ok,{RemoteAddr,RemotePort}} = inet:peername(Socket),
            RemoteAddrBytes = helpers:addr_to_bytes(RemoteAddr),
            RemotePortBytes = helpers:integer_to_2byte_binary(RemotePort),

            ConnStateMsg = io_lib:format("Connection received to BIND from ~s:~B", [inet:ntoa(RemoteAddr), RemotePort]),
            socks_worker:log_notice(State#state.workerId, ConnStateMsg),

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
                    gen_tcp:send(State#state.socket, <<?REP_VERSION, ?REQ_GRANTED, RemotePortBytes/binary, RemoteAddrBytes/binary>>);
                _ ->
                    socks_worker:log_warning(State#state.workerId, "Connection received from wrong host"),
                    gen_tcp:send(State#state.socket, <<?REP_VERSION, ?REQ_REJECTED_OR_FAILED, RemotePortBytes/binary, RemoteAddrBytes/binary>>),
                    gen_tcp:shutdown(State#state.socket, write),
                    gen_tcp:close(ListenSocket)
            end,

            {noreply, State#state{stage=#stage.connect, connectSocket=Socket}};
        {error, _} ->

            socks_worker:log_warning(State#state.workerId, "Error accepting connection"),

            % communicate error
            gen_tcp:send(State#state.socket, <<?REP_VERSION, ?REQ_REJECTED_OR_FAILED, 0,0,0,0, 0,0>>),
            gen_tcp:shutdown(State#state.socket, write),
            gen_tcp:close(ListenSocket),
            {stop, normal, State}
    end.

