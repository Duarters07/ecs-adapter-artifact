# rsync 3.2.7 daemon - log file

Source: rsyncd.conf(5) ("log file", "log format") and rsync(1) (https://download.samba.org/pub/rsync/rsyncd.conf.5),
Debian package. With `--log-file` the daemon writes one line per event:

    <timestamp> [<pid>] <message>

## The messages kept

    connect from <client_name> (<client_ip>)
    rsync allowed access on module <module> from <client_name> (<client_ip>)
    auth failed on module <module> from <client_name> (<client_ip>) for <user>: <reason>
    unknown module '<module>' tried from <client_name> (<client_ip>)

- `timestamp` - local time `YYYY/MM/DD hh:mm:ss`; `pid` - the process serving the connection
- `client_name` - the client's reverse-DNS name, `UNDETERMINED` with `reverse lookup = no`; `client_ip` - its address
- `module` - the module requested; `user` - the rsync account presented
- `reason` - why authentication failed: `password mismatch`, or `no matching rule` for an account the module does
  not list
