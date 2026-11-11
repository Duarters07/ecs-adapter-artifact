FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    HF_HOME=/app/.cache/huggingface

# The V3 sandbox launches an isolated Logstash container, so this image needs
# the docker CLI. See stack/docker-compose.yml for the privilege note.
#
# `docker-cli`, NOT `docker.io`. Debian 13 split the package: `docker.io` now
# ships the daemon alone and the client moved out. Installing it here succeeded,
# reported nothing, and left no /usr/bin/docker - which surfaced as every V3 run
# failing in 0.0s, a whole corpus of ninety recorded as parser failures when the
# cause was a missing binary. This container never runs a daemon; it only ever
# talks to the host's socket, so the client is the right package regardless.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates docker-cli \
    && rm -rf /var/lib/apt/lists/* \
    && docker --version

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download the embedding model so runs are offline and reproducible.
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"

# Set only AFTER the download, so the build can still fetch it. Two reasons:
# it makes the "offline and reproducible" claim above enforced rather than
# merely intended, and it stops the hub trying to write bookkeeping files back
# into a cache that belongs to the image's uid. The container runs as the
# invoking user (see the `user:` note in stack/docker-compose.yml), so those
# writes fail; the hub ignores the error, but it prints two lines of noise per
# run before doing so.
ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

COPY adapter/    ./adapter/
COPY validators/ ./validators/
COPY bench/      ./bench/
COPY prompts/    ./prompts/
COPY schema/     ./schema/
COPY tests/      ./tests/
# Phase 1 and the live experiment run in this container too: `make ecs-generate`
# execs `python -m teacher.generate` here, and it needs the package to exist.
COPY teacher/    ./teacher/
COPY training/   ./training/
COPY testbed/    ./testbed/

# A FALLBACK IDENTITY, NOT THE ONE THE STACK USES. Compose overrides this with
# the invoking user's uid:gid, because every writable path in the running
# container is a bind mount of a host directory that the host venv also writes.
# This user is what `docker run` on the image alone gets, and it exists so that
# the image is never root by default.
RUN useradd --create-home --uid 10001 adapter \
    && mkdir -p /app/results /app/candidates /app/ecs \
                /app/teacher/out /app/training/data /app/testbed/runs \
    && chown -R adapter:adapter /app
USER adapter

ENTRYPOINT ["python", "-m", "adapter.main"]
CMD ["--help"]
