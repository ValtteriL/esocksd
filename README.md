esocksd
=====

esocksd is a robust SOCKS proxy server daemon. 

As an OTP application, esocksd is aimed for serving LARGE number of clients.


Features
-----
- [SOCKS 4](https://www.openssh.com/txt/socks4.protocol) + [4A](https://www.openssh.com/txt/socks4a.protocol)
- SOCKS 5 + 5h ([RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928))
- Username/Password authentication mode ([RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929))
- Restricting allowed SOCKS commands
- Restricting access to networks
- Comprehensive logging
- Multi interface and port operation
- IPv4 + IPv6 support


Install
-----

    $ mkdir esocksd && cd esockds
    $ wget https://github.com/ValtteriL/esocksd/releases/download/1.0.0/esocksd-1.0.0.tar.gz
    $ tar -zxvf esocksd-1.0.0.tar.gz
    $ export PATH=$PATH:$PWD/bin
    $ esocksd


Usage
-----

Run on foreground:
    
    $ esocksd foreground

Run in background as daemon and stop:

    $ esocksd daemon
    $ esocksd stop

Attach to running node (for debugging purposes):

    $ esocksd remote_console

Show usage:
    
    $ esocksd


Build from source (requires [rebar3](https://rebar3.org/))
-----

    $ rebar3 tar


Configuration
-----

esocksd is configured in sys.config.src that you can find in the releases/1.0.0/ directory.


The configuration looks as follows:

```
{listenaddress, ["0.0.0.0", "::"]}, 
{port, [${PORT:-1080}]}, 
{loglevel, ${LOGLEVEL:-notice}}, 
{logfile, "${LOGFILE:-esocksd.log}"}, 
{authmethod, ${AUTHMETHOD:-none}},
{allowcommands, [connect, bind, udp_associate]},
{networkacl, [
    {allow, "0.0.0.0/0"},
    {block, "255.255.255.255/31"}
]},
{networkacl6, [
    {allow, "::/0"}
    ]},
{userpass, []}
```

### listenaddress
Specifies the local addresses esocksd should listen on.
Specified as a list of strings. Example: `["0.0.0.0", "::"]`
The default is to listen on all local addresses.

### port
Specifies the port number that esocksd listens on. 
Specified as a list of strings. Example: `[1080, 1081]`
The default is `[1080]`.

Can be overwritten with environment variable PORT. Example: `PORT=1080 esocksd`.

### loglevel
Gives the verbosity level that is used when logging messages from esocksd. The possible values are: 
emergency | alert | critical | error | warning | notice | info | debug
The default is `notice`.

Can be overwritten with environment variable LOGLEVEL. Example: `LOGLEVEL=debug esocksd`.

### logfile
File to write log output to. Specified as a string.
Example: `esocksd.log`.

Can be overwritten with environment variable LOGFILE. Example: `LOGFILE=/dev/null esocksd`

### authmethod
Authentication method used. The possible values are:
none | userpass
none = no authentication required
userpass = username + password authentcation required (disables SOCKS4 as it does not support authentication)
The default is `none`.

Can be overwritten with environment variable AUTHMETHOD. Example: `AUTHMETHOD=userpass esocksd`

### allowcommands
SOCKS commands that are allowed. The possible values are: 
connect | bind | udp_associate
Specified as a list of atoms. Example: `[connect, bind, udp_associate]`.
The defauls is `[connect, bind, udp_associate]`.

### networkacl
Which IPv4 networks to allow users to connect to. Evaluated in order from top to bottom.
Specified as a list of tuples. The possible tuples are of form {allow|block, network}.
Example: `[{allow, "0.0.0.0/0"}, {block, "255.255.255.255/31"}]`.
The default is to allow all networks except localhost.

### networkacl6
Same as networkacl but for IPv6.
Example: `[{allow, "::/0"}]`
The default is to allow all networks except localhost.

### userpass
Usernames and passwords for password authentication.
Specified as list of tuples. The tuples are of form {username, password}.
Example: `[{"username", "password"},{"admin", "secret"}]`.
By default there are no usernames or passwords.


Support
-----
If you are having problems with esocksd, please raise an issue on Github.


Contributing
-----
Contributions are welcome. You can contribute by cloning the repository and creating a pull request.


TODO (for future releases)
-----
- per-user ACL