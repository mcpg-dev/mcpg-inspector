# mcpg-inspector

MCP inspector for mcpg: connect to MCP servers over stdio or
streamable HTTP, exercise every protocol surface (tools, resources,
prompts, completions, server→client interactions, auth) and watch the
raw wire while doing it — as a web UI, a terminal UI, or one-shot CLI
verbs. Runs standalone, supervised by the gateway
(`mcpg --config server.yml --inspector`), or hosted.

One engine, three faces: the web UI, the terminal UI, and the CLI verbs
all drive the same `/api/v1` surface this server exposes.

The full inspector ships as the image `ghcr.io/mcpg-dev/mcpg-inspector`, or
builds from this repository with `cargo build --release`. The signed release
tarballs on this repository's Releases page carry the terminal UI alone,
`mcpg-inspector-tui` (also the image `ghcr.io/mcpg-dev/mcpg-inspector-tui`).
Install it with:

```sh
curl -fsSL https://raw.githubusercontent.com/mcpg-dev/mcpg/main/install.sh | sh -s -- --bin mcpg-inspector-tui
```

This repository is a read-only mirror — issues welcome here, code
changes happen upstream.
