"""V3 - sandbox replay.

Catches: broken grok patterns, runtime failures, events lost in transformation.

The generated parser is UNTRUSTED until V4 passes, so it runs in a throwaway
container with no network at all. It must not be able to reach Kafka or
Elasticsearch.
"""
from __future__ import annotations

from pathlib import Path
import json
import os
import subprocess
import tempfile

from adapter.types import STAGE_INTERPRET, STAGE_MAP, Finding, Source, ValidationReport, round9_pipeline

# `exit_after_read` is the difference between a rung and a hang.
#
# Logstash's file input in `mode => "read"` reads the file and then keeps the
# pipeline ALIVE, waiting for more. Without this option the sandbox never
# terminates: the parser runs, the output is written, and the container sits
# there until the client's timeout kills it - reporting `logstash_timeout` for a
# candidate that was in fact fine, and leaving the container orphaned because
# `--rm` only fires on a clean exit.
#
# `file_completed_action` defaults to `delete` in read mode, which would remove
# the input from under a re-run; the work directory is temporary, but logging is
# cheaper than a surprise.
SANDBOX_TEMPLATE = """\
input {{ file {{ path => "/work/input.log" mode => "read"
        sincedb_path => "/dev/null" start_position => "beginning"
        exit_after_read => true
        file_completed_action => "log"
        file_completed_log_path => "/work/completed.log" }} }}
{filter_block}
output {{ file {{ path => "/work/output.ndjson" codec => json_lines }} }}
"""


# Lines that name the cause, picked out of a start-up log that is mostly
# deprecation notices and license-checker complaints. The sandbox runs with
# --network none, so "Elasticsearch Unreachable" and "name resolution" are
# expected there and say nothing about the candidate.
_NOISE = (
    "deprecat", "license", "xpack", "monitoring", "UnknownHostException",
    "name resolution", "Elasticsearch Unreachable", "bundled JDK",
)
_SIGNAL = ("ConfigurationError", "Duplicate keys", "Expected one of",
           "error", "Error", "ERROR", "exception", "Exception")


# WHERE THE SANDBOX'S WORKING DIRECTORY HAS TO LIVE.
#
# V3 launches a SIBLING container through the host's Docker socket, so the
# `-v <dir>:/work` path is resolved by the daemon ON THE HOST. A temporary
# directory created inside this container does not exist there, and Logstash
# starts with an empty /work:
#
#     [ERROR][logstash.config.sourceloader] No configuration found in the
#     configured sources.
#
# which reads as a broken candidate and is nothing of the kind. Running V3 from
# the host works and hid this for as long as nobody ran it from inside.
#
# The fix is a directory bind-mounted at the SAME path on both sides, named by
# ECS_SANDBOX_DIR. Outside a container the variable is unnecessary and any
# temporary directory will do.
SANDBOX_DIR_ENV = "ECS_SANDBOX_DIR"

# HOW MUCH CPU THE SANDBOX GETS, AND WHY IT IS NOT A SECURITY SETTING.
#
# The containment boundary is `--network none`, `--memory` and
# `no-new-privileges`: an untrusted parser cannot reach the network, cannot
# exhaust the host's memory and cannot gain privileges. The CPU share is none of
# those. It bounds how fast the candidate runs, not what it can do.
#
# It was set to 1, and Logstash start-up - JVM, JRuby, plugin registration -
# parallelises. Measured on the same host, same pipeline, same eleven events:
#
#     --cpus 1   136 s
#     --cpus 4    32 s
#
# The ladder runs one sandbox for V3 and one per scenario for V4, so that factor
# multiplies across every candidate: a ninety-proposal validation run went from
# roughly two hours to seven.
SANDBOX_CPUS_ENV = "ECS_SANDBOX_CPUS"
SANDBOX_MEMORY_ENV = "ECS_SANDBOX_MEMORY"
DEFAULT_SANDBOX_CPUS = "4"
DEFAULT_SANDBOX_MEMORY = "1g"


# NATIVE MODE: LOGSTASH AS A LOCAL PROCESS, FOR HOSTS WITHOUT DOCKER.
#
# A rented GPU instance is itself an unprivileged container and cannot run
# Docker, so the whole of Phase 1 used to be split: generate on the card, carry
# the proposals home, validate where Docker works. That split is what made a
# laptop going to sleep, or a Wi-Fi change, cost hours (PHASE1A_RENTED_GPU.md).
# Pointing ECS_SANDBOX_LOGSTASH at a Logstash binary of the same version runs
# the identical template, plugins and version as a plain subprocess.
#
# WHAT IS GIVEN UP, STATED: the container's `--network none` and its memory cap.
# The parser cannot reach configuration it was not compiled to - the compiler
# emits only grok, kv, json, csv, date, translate and mutate, none of which does
# network I/O - so network isolation was defence in depth, not the boundary.
# The heap is still capped through LS_JAVA_OPTS. Use it on a disposable host
# that validates corpus proposals, not on the SME's server; the deployment
# watcher keeps the containerised sandbox.
NATIVE_ENV = "ECS_SANDBOX_LOGSTASH"


def _native_bin() -> str | None:
    return os.environ.get(NATIVE_ENV, "").strip() or None


def _limit(var: str, default: str) -> str:
    return os.environ.get(var, "").strip() or default



def _in_container() -> bool:
    return Path("/.dockerenv").exists()


def _sandbox_base() -> str | None:
    """The directory to create the work area in, or None for the default."""
    base = os.environ.get(SANDBOX_DIR_ENV, "").strip()
    return base or None


def _sandbox_unusable() -> str | None:
    """Why V3 cannot run here, or None if it can."""
    native = _native_bin()
    if native:
        if not (Path(native).is_file() and os.access(native, os.X_OK)):
            return f"{NATIVE_ENV} is {native!r}, which is not an executable file."
        return None
    base = _sandbox_base()
    if base:
        if not Path(base).is_dir():
            return (
                f"{SANDBOX_DIR_ENV} is {base!r} but that directory does not exist. "
                "It must be bind-mounted at the same path on the host and in this "
                "container, because the sandbox is a sibling container and its -v "
                "path is resolved by the host's daemon."
            )
        # Existing is not enough. Docker creates a missing bind-mount source as
        # root, and this process runs as the invoking user, so the failure
        # arrives as a PermissionError from inside tempfile - many frames from
        # anything that names the cause.
        if not os.access(base, os.W_OK | os.X_OK):
            import pwd

            st = Path(base).stat()
            try:
                owner = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                owner = str(st.st_uid)
            return (
                f"{SANDBOX_DIR_ENV} is {base!r} and this process (uid {os.getuid()}) "
                f"cannot write to it; it is owned by {owner} with mode "
                f"{st.st_mode & 0o777:o}. Docker creates a missing bind-mount "
                "source as root, so this usually means the directory was removed "
                "and recreated at mount time. Fix the ownership on the HOST and "
                "restart the container."
            )
        return None
    if _in_container():
        return (
            f"{SANDBOX_DIR_ENV} is not set and this process is in a container. "
            "V3 launches a sibling container through the host's Docker socket, "
            "so its -v path is resolved on the HOST: a temporary directory made "
            "in here does not exist there and Logstash would start with an empty "
            "/work. Set ECS_SANDBOX_DIR to a directory mounted at the same path "
            "on both sides, or run V3 from the host."
        )
    return None


def _salient(output: str) -> str:
    """The lines worth putting in a finding, or the tail if none stand out."""
    hits = [
        line.strip() for line in output.splitlines()
        if any(s in line for s in _SIGNAL)
        and not any(n in line for n in _NOISE)
    ]
    return "\n".join(hits)[:1200] if hits else output[-800:]


def _many_template(n: int) -> str:
    """N inputs, one output each, ONE Logstash.

    WHY ONE PROCESS. Start-up - JVM, JRuby, plugin registration - is most of a
    sandbox run, and the ladder used to pay it 1 + N times per candidate: V3 on
    the samples, then once per V4 scenario. Measured on the rented card under
    load, a candidate with two scenarios took ~235 s, almost all of it three
    start-ups. Each input here is tagged in @metadata, which no codec writes,
    and routed to its own output file, so every scenario still gets exactly the
    documents its own events produced - the same documents three processes
    would have produced, from the same filter.
    """
    inputs = "\n".join(
        f'  file {{ path => "/work/input-{i}.log" mode => "read"\n'
        f'        sincedb_path => "/dev/null" start_position => "beginning"\n'
        f'        exit_after_read => true\n'
        f'        file_completed_action => "log"\n'
        f'        file_completed_log_path => "/work/completed-{i}.log"\n'
        f'        add_field => {{ "[@metadata][sbx]" => "{i}" }} }}'
        for i in range(n))
    outputs = "\n".join(
        f'  if [@metadata][sbx] == "{i}" {{ file {{ path => "/work/output-{i}.ndjson" '
        f'codec => json_lines }} }}'
        for i in range(n))
    return ("input {\n" + inputs + "\n}\n{filter_block}\noutput {\n" + outputs + "\n}\n")


def validate(
    pipeline_filter: str,
    source: Source,
    stack_version: str,
    timeout_s: int = 240,
) -> ValidationReport:
    return validate_many(pipeline_filter, [source], stack_version, timeout_s)[0]


def validate_many(
    pipeline_filter: str,
    sources: list[Source],
    stack_version: str,
    timeout_s: int = 240,
) -> list[ValidationReport]:
    """One report per source, from a single Logstash run. See `_many_template`."""
    reps = [ValidationReport(rung_reached="V3") for _ in sources]
    many = len(sources) > 1

    # Fail on the arrangement, not on the candidate. Without this the symptom is
    # an empty /work and a finding that blames the parser.
    unusable = _sandbox_unusable()
    if unusable:
        for rep in reps:
            rep.findings.append(Finding("V3", "sandbox_unusable", unusable, STAGE_MAP))
        return reps

    with tempfile.TemporaryDirectory(dir=_sandbox_base()) as tmp:
        work = Path(tmp)
        # Samples AND the probe. V3.5 asks where the probe's values landed, so
        # the parser has to have been given them.
        names_in = [f"input-{i}.log" for i in range(len(sources))] if many else ["input.log"]
        names_out = [f"output-{i}.ndjson" for i in range(len(sources))] if many else ["output.ndjson"]
        for src, name in zip(sources, names_in):
            (work / name).write_text("\n".join(src.parser_input()) + "\n", encoding="utf-8")
        native = _native_bin()
        template = _many_template(len(sources)) if many else SANDBOX_TEMPLATE
        if native:
            # The container sees the work area at /work; a local process sees
            # it where it is. Nothing else in the template changes.
            template = template.replace('"/work/', f'"{work}/')
        (work / "pipeline.conf").write_text(
            template.replace("{filter_block}", pipeline_filter) if many
            else template.format(filter_block=pipeline_filter), encoding="utf-8"
        )
        for name in names_out:
            (work / name).touch()
            os.chmod(work / name, 0o666)
        # Logstash runs as uid 1000 inside the image and must be able to write.
        os.chmod(work, 0o777)

        env = None
        if native:
            cmd = [
                native,
                "-f", str(work / "pipeline.conf"),
                "--path.data", str(work / "lsdata"),
                "--path.logs", str(work / "lslogs"),
                "--log.level", "warn",
            ]
            # C1-only JIT and the serial collector: a sandbox run is a few
            # seconds of work after start-up, so the JVM's optimising tier never
            # pays for itself. Measured on the card: ~20% off each run.
            env = {**os.environ, "LS_JAVA_OPTS":
                   "-Xms512m -Xmx512m -XX:TieredStopAtLevel=1 -XX:+UseSerialGC"}
        else:
            cmd = [
                "docker", "run", "--rm",
                "--network", "none",
                "--memory", _limit(SANDBOX_MEMORY_ENV, DEFAULT_SANDBOX_MEMORY),
                "--cpus", _limit(SANDBOX_CPUS_ENV, DEFAULT_SANDBOX_CPUS),
                "--security-opt", "no-new-privileges:true",
                "-v", f"{work}:/work",
                "-e", "LS_JAVA_OPTS=-Xms512m -Xmx512m",
                f"docker.elastic.co/logstash/logstash:{stack_version}",
                "logstash",
                "-f", "/work/pipeline.conf",
                "--path.data", "/tmp/ls",
                "--log.level", "warn",
            ]
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                cmd, capture_output=True, text=True, timeout=timeout_s, check=False,
                env=env,
            )
            # BOTH STREAMS, AND stdout FIRST.
            #
            # Logstash writes its configuration errors to stdout; stderr carries
            # little more than the JDK banner. Reporting stderr alone produced
            # the finding "Using bundled JDK: /usr/share/logstash/jdk" for a
            # pipeline that had been refused outright with
            # "Duplicate keys found in your configuration", and diagnosing it
            # took four manual runs of the sandbox by hand.
            #
            # The tail is kept rather than the head because the cause is at the
            # end, after the deprecation warnings every start-up emits.
            output = (proc.stdout or "") + (proc.stderr or "")
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            for rep in reps:
                rep.findings.append(
                    Finding("V3", "logstash_timeout",
                            f"Logstash did not finish within {timeout_s}s.", STAGE_MAP)
                )
            return reps
        except FileNotFoundError:
            for rep in reps:
                rep.findings.append(
                    Finding("V3", "docker_unavailable",
                            "docker is not available to this process. V3 needs it.", STAGE_MAP)
                )
            return reps

        for rep, src, name in zip(reps, sources, names_out):
            _judge(rep, src, (work / name).read_text(encoding="utf-8").strip(),
                   returncode, output)
    return reps


def _judge(rep: ValidationReport, source: Source, text: str, returncode: int,
           output: str) -> None:
    if returncode != 0 and not text:
        rep.findings.append(
            Finding("V3", "logstash_failed",
                    _salient(output) or "Logstash produced no output at all.",
                    STAGE_MAP)
        )
        return

    docs = []
    for line in text.splitlines():
        try:
            docs.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    expected = len(source.parser_input())
    # Lines lost or tagged unparsed are an EXTRACTION fault, and the extraction
    # is stage 1's (round 10, A1). Round 9 sent them to stage 2, which never
    # sees a line and cannot change the extraction.
    extraction_stage = STAGE_MAP if round9_pipeline() else STAGE_INTERPRET
    if len(docs) < expected:
        rep.findings.append(
            Finding(
                "V3",
                "events_lost",
                f"{expected} events in, {len(docs)} out.",
                extraction_stage,
            )
        )

    for d in docs:
        for t in d.get("tags", []) or []:
            if str(t).endswith("_parse_failure"):
                rep.findings.append(
                    Finding(
                        "V3",
                        "parse_failure_tag",
                        f"event tagged {t}: {str(d.get('message', ''))[:160]}",
                        extraction_stage,
                    )
                )
                break

    rep.metrics["documents"] = docs
    rep.passed = not rep.findings
