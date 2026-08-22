use std::net::SocketAddr;

/// Flags for `mcpg-inspector serve`. Every flag has an
/// `MCPG_INSPECTOR_*` env twin so hosted deployments configure via
/// environment and the gateway supervisor passes flags gap-only.
#[derive(clap::Args, Debug)]
pub struct ServeArgs {
    /// host:port serving the web UI and API (single origin)
    #[arg(long, env = "MCPG_INSPECTOR_BIND", default_value = "127.0.0.1:7846")]
    pub bind: SocketAddr,

    /// Development mode: verbose logs
    #[arg(long, env = "MCPG_INSPECTOR_DEV")]
    pub dev: bool,

    /// Pre-wired target (repeatable): an http(s) URL,
    /// `stdio:<command> [args…]`, or a JSON target object. The gateway
    /// supervisor passes its own endpoint this way; the matching
    /// credential arrives via `MCPG_INSPECTOR_GATEWAY_TOKEN`, never
    /// argv.
    #[arg(long = "target", value_name = "SPEC")]
    pub targets: Vec<String>,

    /// Pin the session token instead of minting one per boot
    #[arg(long, env = "MCPG_INSPECTOR_SESSION_TOKEN")]
    pub session_token: Option<String>,

    /// Serve without a session token. Loopback binds only.
    #[arg(long, env = "MCPG_INSPECTOR_AUTH_NONE")]
    pub auth_none: bool,

    /// Bind every interface. The API can spawn processes, so exposing
    /// it beyond this host is an explicit, ugly opt-in.
    #[arg(long, env = "MCPG_INSPECTOR_BIND_ALL")]
    pub dangerously_bind_all_interfaces: bool,

    /// Hosted profile: no stdio targets, no private-address egress
    #[arg(long, env = "MCPG_INSPECTOR_HOSTED")]
    pub hosted: bool,

    /// Frames retained per target (oldest drop first)
    #[arg(long, env = "MCPG_INSPECTOR_FRAME_BUFFER", default_value_t = 10_000)]
    pub frame_buffer: usize,

    /// Open the printed URL in a browser
    #[arg(long = "open", env = "MCPG_INSPECTOR_OPEN")]
    pub open_browser: bool,

    /// Sustained requests per minute per client address. Applies in
    /// hosted mode only; 0 disables.
    #[arg(long, env = "MCPG_INSPECTOR_RATE_LIMIT_PER_MIN", default_value_t = 600)]
    pub rate_limit_per_min: u32,

    /// Burst allowance for the per-address limiter.
    #[arg(long, env = "MCPG_INSPECTOR_RATE_LIMIT_BURST", default_value_t = 120)]
    pub rate_limit_burst: u32,

    // ── hosted identity ────────────────────────────────────────────
    // Required in hosted mode and refused outside it: a shared
    // deployment must know who is calling, and a loopback one has no
    // provider to ask.
    /// OIDC issuer URL. Required with --hosted.
    #[arg(long, env = "MCPG_INSPECTOR_OIDC_ISSUER", value_name = "URL")]
    pub oidc_issuer: Option<String>,

    /// OIDC client id. Required with --hosted.
    #[arg(long, env = "MCPG_INSPECTOR_OIDC_CLIENT_ID", value_name = "ID")]
    pub oidc_client_id: Option<String>,

    /// OIDC client secret. Omit for a public client — PKCE is sent
    /// either way.
    #[arg(long, env = "MCPG_INSPECTOR_OIDC_CLIENT_SECRET", value_name = "SECRET")]
    pub oidc_client_secret: Option<String>,

    /// Public origin this instance is reached at, e.g.
    /// `https://inspector.mcpg.cloud`. Required with --hosted: the OIDC
    /// redirect URI and the browser origin allow-list both derive from
    /// it, and neither can be inferred from a bind behind a proxy.
    #[arg(long, env = "MCPG_INSPECTOR_PUBLIC_URL", value_name = "URL")]
    pub public_url: Option<String>,

    /// Concurrent signed-in sessions; 0 is unlimited.
    #[arg(long, env = "MCPG_INSPECTOR_MAX_SESSIONS", default_value_t = 500)]
    pub max_sessions: usize,

    /// Targets one signed-in user may hold at once; 0 is unlimited.
    #[arg(long, env = "MCPG_INSPECTOR_MAX_TARGETS", default_value_t = 20)]
    pub max_targets: usize,
}
