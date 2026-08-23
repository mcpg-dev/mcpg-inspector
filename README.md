# mcpg-inspector

MCP inspector for mcpg: connect to MCP servers over stdio or
streamable HTTP, exercise every protocol surface (tools, resources,
prompts, completions, server→client interactions, auth) and watch the
raw wire while doing it — as a web UI, a terminal UI, or one-shot CLI
verbs. Runs standalone, supervised by the gateway
(`mcpg --config server.yml --inspector`), or hosted.

One engine, three faces: the web UI, the terminal UI, and the CLI verbs
all drive the same `/api/v1` surface this server exposes.

Signed release tarballs live on this repository's Releases page. Install:

```sh
curl -fsSL https://raw.githubusercontent.com/mcpg-dev/source-code/main/install.sh | sh -s -- --bin mcpg-inspector
```

This repository is a read-only mirror — issues welcome here, code
changes happen upstream.
