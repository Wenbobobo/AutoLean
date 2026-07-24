# syntax=docker/dockerfile:1

FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS lean-archive-verifier

ARG LEAN_ARCHIVE=lean-4.28.0-linux.tar.zst
ARG LEAN_ARCHIVE_SHA256=ceb3a3f844f7aebf63245e2b51c28d5b0ed38942c19f93cf3febd520302160bd

COPY ${LEAN_ARCHIVE} /tmp/${LEAN_ARCHIVE}
RUN printf '%s  %s\n' "${LEAN_ARCHIVE_SHA256}" "/tmp/${LEAN_ARCHIVE}" \
      | sha256sum --check --strict - \
    && printf '%s\n' "${LEAN_ARCHIVE_SHA256}" > /lean-archive.sha256

FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

ARG LEAN_ARCHIVE=lean-4.28.0-linux.tar.zst
ARG LEAN_ARCHIVE_SHA256=ceb3a3f844f7aebf63245e2b51c28d5b0ed38942c19f93cf3febd520302160bd

LABEL org.opencontainers.image.title="AutoLean pure-Lean verifier worker" \
      org.opencontainers.image.description="Minimal Lean 4.28.0 verifier; no mathlib" \
      org.opencontainers.image.version="4.28.0-pure-v3" \
      org.opencontainers.image.base.digest="sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90" \
      org.autolean.lean.archive.sha256="${LEAN_ARCHIVE_SHA256}" \
      org.autolean.wrapper.protocol="autolean.oci-lean-wrapper.v2"

# Docker extracts the zstd-compressed tar archive by content. The first stage verifies that exact
# build-context byte stream; copying its marker makes the final image depend on that hard gate.
COPY --from=lean-archive-verifier /lean-archive.sha256 /opt/lean-archive.sha256
ADD ${LEAN_ARCHIVE} /opt/

RUN test -x /opt/lean-4.28.0-linux/bin/lean \
    && test "$(cat /opt/lean-archive.sha256)" = "${LEAN_ARCHIVE_SHA256}" \
    && ln -s /opt/lean-4.28.0-linux /opt/lean \
    && mkdir -p /opt/autolean/bin /opt/autolean/lib /input /source /deps /work

ENV PATH="/opt/lean/bin:${PATH}" \
    LEAN_PATH="/opt/lean/lib/lean"

COPY AutoleanLeanQuery.lean /opt/autolean/lib/AutoleanLeanQuery.lean
COPY autolean-lean-wrapper /opt/autolean/bin/autolean-lean-wrapper

RUN chmod 0444 /opt/autolean/lib/AutoleanLeanQuery.lean \
    && chmod 0555 /opt/autolean/bin/autolean-lean-wrapper \
    && lean --version \
    && lean -o /opt/autolean/lib/AutoleanLeanQuery.olean \
      /opt/autolean/lib/AutoleanLeanQuery.lean

WORKDIR /work
USER 65532:65532
