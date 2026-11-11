# Rspamd 3.4 - log, console, level info

Source: Rspamd documentation, "logging" configuration (vendor documentation), Debian package. Messages are submitted
to the normal worker's /checkv2 endpoint as an MTA would, with the SMTP client address, HELO, sender and recipient in
the request headers. After each scan the task logs one line (rspamd_task_write_log):

    <yyyy-mm-dd hh:mm:ss> #<pid>(<worker>) <<tag>>; <module>; <function>: id: <<message_id>>, ip: <client_ip>,
    from: <<sender>>, (<metric>: <is_spam> (<action>): [<score>/<required_score>] [<symbols>]), len: <size>,
    time: <time>ms, dns req: <dns_req>, digest: <<digest>>, rcpts: <<rcpts>>, mime_rcpts: <<mime_rcpts>>

(one line; wrapped here)

- `client_ip` - the SMTP client that sent the message; `sender` - the envelope sender; `rcpts` - the envelope
  recipients, `mime_rcpts` - the recipients in the message headers
- `action` - what the MTA is told to do: no action, add header, rewrite subject, greylist, soft reject, reject;
  `is_spam` - T or F; `score` / `required_score` - the message's score and the reject threshold
- `symbols` - the rules that matched, each `NAME(score){options}`
- `message_id` - the Message-ID header (`undef` when absent); `digest` - a digest of the message
- `size` - bytes; `time` - scan time; `dns_req` - DNS requests made; `pid`, `worker`, `tag`, `module`, `function` -
  the process, worker type, task tag and logging place
