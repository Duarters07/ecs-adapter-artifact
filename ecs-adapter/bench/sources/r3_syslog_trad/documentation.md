# Linux authentication log — rsyslog, traditional file format

Source: rsyslog documentation, "Templates" (RSYSLOG_TraditionalFileFormat),
https://www.rsyslog.com/doc/configuration/templates.html

    <timestamp> <host> <program>[<pid>]: <message>

- `timestamp` — `Mmm dd HH:MM:SS`, local time, no year
- `host` — the host name of the machine that logged the message
- `program` — the program that logged it (`sshd`, `sudo`)
- `pid` — that program's process id; sudo writes none

## The messages kept, and the names of their parts

sshd (OpenSSH 9.2):

    Failed password for [invalid user ]<user> from <src_ip> port <src_port> ssh2
    Accepted password for <user> from <src_ip> port <src_port> ssh2
    Invalid user <user> from <src_ip> port <src_port>
    Connection closed by authenticating user <user> <src_ip> port <src_port> [preauth]
    Connection closed by invalid user <user> <src_ip> port <src_port> [preauth]
    Connection closed by <src_ip> port <src_port>
    error: kex_exchange_identification: <reason>

sudo (1.9):

    <user> : PWD=<cwd> ; USER=<target_user> ; COMMAND=<command>
    <user> : <sudo_result> ; PWD=<cwd> ; USER=<target_user> ; COMMAND=<command>

- `outcome` — the word `Failed` or `Accepted`
- `user` — the account that tried to log in, or that ran sudo
- `src_ip`, `src_port` — the address and port the ssh client connected from
- `reason` — why the ssh key exchange did not start
- `sudo_result` — why sudo refused: `1 incorrect password attempt`, `user NOT in sudoers`
- `cwd` — the directory sudo was run in
- `target_user` — the account the command was to run as
- `command` — the command line sudo was asked to run
