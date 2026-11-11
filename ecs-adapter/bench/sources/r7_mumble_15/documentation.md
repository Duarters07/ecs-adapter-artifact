# Mumble server 1.5.735 - log on stderr (foreground)

Source: Mumble server documentation (mumble-server.ini: "serverpassword", "logfile"), Debian package. One line per
event, tagged with the virtual server and the client session:

    <<level>><yyyy-mm-dd hh:mm:ss.mmm> <server_id> => <<session>:<user>(<user_id>)> <message>

The session number before authentication is always 0; the real one appears from `Authenticated` or `Rejected connection` on. `user` is empty until the client has sent its name; `user_id` is -1 for an unregistered user.

## The messages kept

    New connection: <client_ip>:<client_port>
    Client version <client_version> (<client_os>: <client_release>)
    Authenticated
    Rejected connection from <client_ip>:<client_port>: <reason>
    Connection closed: <close_reason> [<close_code>]

- `level` - W (warning) for these lines; `server_id` - the virtual server
- `client_ip`, `client_port` - the client; `client_release` - the client's release; `client_os` - its operating
  system and, from 1.4 on, its version (`Win 10.0.19045`)
- `reason` - why the login was refused (Invalid server password; Wrong certificate or password for existing user)
