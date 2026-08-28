# mcpg-inspector-ui

The inspector's web UI. It is not served from this directory at runtime and
has no deployable artefact of its own: the build writes into the inspector
server's crate, which embeds the result **at compile time** behind the
server's `embedded-ui` feature. The thing you ship is the server binary.

```sh
pnpm --filter mcpg-inspector-ui dev        # vite dev server, talks to a running inspector
pnpm --filter mcpg-inspector-ui build      # writes the server's static/ directory
pnpm --filter mcpg-inspector-ui typecheck
```

## Why the output path points outside this directory

`vite.config.ts` sets `outDir` to the inspector server's `static/`, because
that is the exact path the server embeds with
`include_dir!("$CARGO_MANIFEST_DIR/static")`. The two are one setting in two
files and only work when they agree.

**If a build cannot find the assets, do not repoint `outDir` to fix it.**
`include_dir!` embeds an empty directory rather than failing, so a wrong path
produces a build that succeeds and a server that serves no console — the
failure appears at runtime, far from the change that caused it. Point the
build at the layout instead.

The control-plane console is this app's structural twin and behaves the same
way.
