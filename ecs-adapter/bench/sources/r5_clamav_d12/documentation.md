# ClamAV 1.4.6 - clamd log

Source: clamd.conf(5) (`LogFile`, `LogTime`, `LogClean`, `ExtendedDetectionInfo`), ClamAV
documentation, https://docs.clamav.net/manual/Usage/Configuration.html, and the Debian package's
clamd.conf.

clamd writes to its log file, with `LogTime` on, one line per detection. Files submitted over the
network with the INSTREAM command are named after the client that sent them:

    <timestamp> -> instream(<client_ip>@<client_port>): <signature>(<md5>:<size>) FOUND

Clean scans are not logged (`LogClean` is off, as packaged).

- `timestamp` - local time, `Www Mmm dd HH:MM:SS yyyy`
- `client_ip`, `client_port` - the address and port of the client that submitted the data
- `signature` - the name of the signature that matched; `.UNOFFICIAL` marks a signature from a
  local database rather than the official ones
- `md5`, `size` - the MD5 hash and the size in bytes of the data that matched
  (`ExtendedDetectionInfo`)
- `result` - `FOUND`
