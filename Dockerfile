# syntax=docker/dockerfile:1
# ============================================================================
# MCPG Inspector — release mirror image
# ----------------------------------------------------------------------------
# Self-contained image built from this repository alone. Three stages:
# a Node stage builds the embedded web UI (a pnpm workspace subset:
# apps/inspector/ui + libs/ui), a Rust stage compiles the server with
# the UI embedded (`embedded-ui` → include_dir!(<crate root>/static)),
# and a slim Debian runtime carries the binary as a non-root user.
#
# Sibling crates are consumed by git reference. When a referenced sibling
# is private, the Rust stage takes a fetch token as a BuildKit secret
# (never a layer):
#
#   docker build --secret id=sibling_fetch_token,env=SIBLING_FETCH_TOKEN -t inspector:local .
#
# Without the secret the build still works when every referenced sibling
# is public — fetches just stay anonymous.
# ============================================================================

FROM node:22-bookworm-slim AS console
WORKDIR /src
# The workspace subset: manifests first for layer-cache-friendly installs.
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/inspector/ui/package.json apps/inspector/ui/package.json
COPY libs/ui/package.json libs/ui/package.json
# corepack honours the packageManager pin — no global pnpm install.
RUN corepack enable && pnpm install --frozen-lockfile
COPY apps/inspector/ui apps/inspector/ui
COPY libs/ui libs/ui
# The ui's vite outDir is `../server/static` — right in the monorepo, where
# the server lives beside the ui; in THIS repo the server crate IS the
# root, so the output is bridged to `<root>/static`, the path the crate's
# include_dir! actually embeds. Do not "fix" the vite config instead: the
# monorepo is the source of truth and the mirror adapts.
RUN pnpm --filter mcpg-inspector-ui build \
    && mkdir -p /out \
    && cp -r apps/inspector/server/static /out/static

# ----------------------------------------------------------------------------
FROM rust:1-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake clang libclang-dev perl pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
COPY --from=console /out/static ./static
# Private sibling git fetches authenticate through the BuildKit secret for
# exactly one RUN; the credential file is removed in the same layer.
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
RUN --mount=type=secret,id=sibling_fetch_token \
    set -eu; \
    if [ -s /run/secrets/sibling_fetch_token ]; then \
      git config --global credential.helper store; \
      printf 'https://x-access-token:%s@github.com\n' "$(cat /run/secrets/sibling_fetch_token)" > ~/.git-credentials; \
    fi; \
    cargo build --release --features embedded-ui,tui --bin mcpg-inspector --bin mcpg-inspector-tui; \
    rm -f ~/.git-credentials

# ----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.title="mcpg-inspector" \
      org.opencontainers.image.description="MCP inspector for mcpg — web UI and API" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 mcpg
COPY --from=build /src/target/release/mcpg-inspector /usr/local/bin/mcpg-inspector
USER mcpg
WORKDIR /home/mcpg
EXPOSE 7846
HEALTHCHECK --interval=30s --timeout=3s \
    CMD ["/usr/local/bin/mcpg-inspector", "--version"]
# The binary stays in CMD, not ENTRYPOINT: this is the contract every
# published inspector image has (and the helm chart's `args` name the
# binary accordingly) — keep them in lockstep.
ENTRYPOINT ["tini", "--"]
CMD ["/usr/local/bin/mcpg-inspector", "serve"]

# ----------------------------------------------------------------------------
# Variant image: the interactive terminal client, published as
# ghcr.io/mcpg-dev/mcpg-inspector-tui (see the extra-images pair). The tui
# crate itself is a library — the standalone binary lives in this crate so
# it can dial targets with the same engine the `tui` subcommand uses.
# Run with a TTY:
#
#   docker run -it --rm ghcr.io/mcpg-dev/mcpg-inspector-tui <args>
FROM debian:bookworm-slim AS tui
LABEL org.opencontainers.image.title="mcpg-inspector-tui" \
      org.opencontainers.image.description="MCP inspector for mcpg — interactive terminal client" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 mcpg
COPY --from=build /src/target/release/mcpg-inspector-tui /usr/local/bin/mcpg-inspector-tui
USER mcpg
WORKDIR /home/mcpg
ENTRYPOINT ["tini", "--", "mcpg-inspector-tui"]
