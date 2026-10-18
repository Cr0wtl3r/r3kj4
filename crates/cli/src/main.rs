use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use r3kj4_browser::{BrowserOptions, Flow};
use r3kj4_core::{RuntimeCapture, ScanOptions, ScanReport};
use serde::Deserialize;
use std::{
    io::{self, Write},
    path::PathBuf,
};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "r3kj4",
    version,
    about = "Recover JavaScript source maps and analyze code with OXC",
    after_help = "Runtime capture requires external Chrome/Chromium or a reachable CDP endpoint. Secrets are printed in full."
)]
struct Cli {
    #[arg(long, global = true, help = "Versioned TOML configuration file")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Discover scripts/maps, recover sources and analyze a URL, file or directory
    Scan(Box<ScanArgs>),
    /// Analyze local sources without network access or source-map discovery
    Analyze(AnalyzeArgs),
    /// Print readable code without modifying the input
    Beautify {
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Inspect the executable and optionally connect to a browser
    Doctor {
        #[arg(long)]
        browser: bool,
        #[arg(long)]
        chrome: Option<PathBuf>,
        #[arg(long)]
        cdp_url: Option<String>,
    },
}
#[derive(ValueEnum, Clone, Default)]
enum Format {
    #[default]
    Text,
    Json,
}
#[derive(Args)]
struct Common {
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,
    #[arg(long)]
    timeout: Option<u64>,
    #[arg(long)]
    concurrency: Option<usize>,
    #[arg(long)]
    jobs: Option<usize>,
    #[arg(long)]
    max_depth: Option<usize>,
    #[arg(long)]
    max_pages: Option<usize>,
    #[arg(long)]
    max_artifacts: Option<usize>,
    #[arg(long)]
    max_asset_bytes: Option<usize>,
    #[arg(long)]
    max_body_bytes: Option<usize>,
    #[arg(long)]
    max_total_bytes: Option<usize>,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
}
#[derive(Args)]
struct ScanArgs {
    target: String,
    #[command(flatten)]
    common: Common,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long)]
    offline: bool,
    #[arg(long)]
    skip_analysis: bool,
    #[arg(long)]
    runtime: bool,
    #[arg(long)]
    flow: Option<PathBuf>,
    #[arg(long)]
    chrome: Option<PathBuf>,
    #[arg(long)]
    cdp_url: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    browser_arg: Vec<String>,
    #[arg(long)]
    session: Option<PathBuf>,
    #[arg(long)]
    save_session: Option<PathBuf>,
    #[arg(long)]
    page_timeout: Option<u64>,
    #[arg(long)]
    settle_ms: Option<u64>,
    #[arg(
        long = "header",
        short = 'H',
        help = "Origin-scoped HTTP header: 'Name: value'"
    )]
    headers: Vec<String>,
    #[arg(long, help = "Origin-scoped Cookie header")]
    cookie: Option<String>,
    #[arg(long)]
    credential_origin: Vec<String>,
    #[arg(long)]
    allow_origin: Vec<String>,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    #[arg(long)]
    insecure: bool,
}
#[derive(Args)]
struct AnalyzeArgs {
    target: PathBuf,
    #[command(flatten)]
    common: Common,
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    schema_version: u32,
    runtime: bool,
    scan: ScanOptions,
    browser: BrowserOptions,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            runtime: false,
            scan: ScanOptions::default(),
            browser: BrowserOptions::default(),
        }
    }
}

fn apply_common(options: &mut ScanOptions, common: &Common) {
    if let Some(v) = &common.out {
        options.out = v.clone();
    }
    if !common.only.is_empty() {
        options.only = common.only.clone();
    }
    if let Some(v) = common.timeout {
        options.timeout_secs = v;
    }
    if let Some(v) = common.concurrency {
        options.concurrency = v;
    }
    if let Some(v) = common.jobs {
        options.jobs = v;
    }
    if let Some(v) = common.max_depth {
        options.max_depth = v;
    }
    if let Some(v) = common.max_pages {
        options.max_pages = v;
    }
    if let Some(v) = common.max_artifacts {
        options.max_artifacts = v;
    }
    if let Some(v) = common.max_asset_bytes {
        options.max_asset_bytes = v;
    }
    if let Some(v) = common.max_body_bytes {
        options.max_body_bytes = v;
    }
    if let Some(v) = common.max_total_bytes {
        options.max_total_bytes = v;
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(io::stderr)
        .init();
    let code = match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<i32> {
    let mut config = if let Some(path) = cli.config {
        toml::from_str::<Config>(&std::fs::read_to_string(path)?)
            .context("invalid configuration")?
    } else {
        Config::default()
    };
    ensure!(
        config.schema_version == 1,
        "unsupported configuration schema_version"
    );
    let cancel = CancellationToken::new();
    let signal = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });
    match cli.command {
        Command::Scan(args) => {
            let options = &mut config.scan;
            options.target = args.target;
            apply_common(options, &args.common);
            if let Some(v) = args.base_url {
                options.base_url = Some(v);
            }
            options.offline |= args.offline;
            options.skip_analysis |= args.skip_analysis;
            if let Some(v) = args.cookie {
                options.cookies = Some(v);
            }
            if let Some(v) = args.proxy {
                options.proxy = Some(v);
            }
            if let Some(v) = args.ca_cert {
                options.ca_cert = Some(v);
            }
            options.insecure |= args.insecure;
            options.credential_origins.extend(args.credential_origin);
            options.allow_origins.extend(args.allow_origin);
            for header in args.headers {
                let (name, value) = header
                    .split_once(':')
                    .context("--header requires 'Name: value'")?;
                options
                    .headers
                    .insert(name.trim().into(), value.trim().into());
            }
            let browser = &mut config.browser;
            if let Some(path) = args.flow {
                browser.flow = Some(
                    toml::from_str::<Flow>(&std::fs::read_to_string(path)?)
                        .context("invalid flow")?,
                );
            }
            if let Some(v) = args.chrome {
                browser.chrome = Some(v);
            }
            if let Some(v) = args.cdp_url {
                browser.cdp_url = Some(v);
            }
            if let Some(v) = args.session {
                browser.session = Some(v);
            }
            if let Some(v) = args.save_session {
                browser.save_session = Some(v);
            }
            if let Some(v) = args.page_timeout {
                browser.page_timeout_secs = v;
            }
            if let Some(v) = args.settle_ms {
                browser.settle_ms = v;
            }
            browser.chrome_args.extend(args.browser_arg);
            let runtime = config.runtime || args.runtime;
            ensure!(
                runtime
                    || browser.flow.is_none()
                        && browser.session.is_none()
                        && browser.save_session.is_none()
                        && browser.cdp_url.is_none(),
                "flow/session/CDP options require --runtime"
            );
            ensure!(
                !runtime || !options.offline,
                "--runtime conflicts with --offline"
            );
            if runtime {
                let url = url::Url::parse(&options.target)
                    .context("--runtime requires an HTTP(S) target")?;
                ensure!(
                    matches!(url.scheme(), "http" | "https"),
                    "--runtime requires an HTTP(S) target"
                );
            }
            ensure!(
                !options.out.exists(),
                "output already exists: {} (choose a new --out)",
                options.out.display()
            );
            r3kj4_core::scan::validate_options(options)?;
            let capture = if runtime {
                eprintln!("[runtime] capturing {}", options.target);
                r3kj4_browser::capture(options, browser, cancel.clone()).await
            } else {
                RuntimeCapture::default()
            };
            eprintln!("[scan] collecting and analyzing {}", options.target);
            let report = r3kj4_core::scan(options.clone(), capture, cancel).await?;
            print_report(&report, &args.common.format)?;
            Ok(if report.coverage.partial { 3 } else { 0 })
        }
        Command::Analyze(args) => {
            config.scan.target = args.target.to_string_lossy().into_owned();
            apply_common(&mut config.scan, &args.common);
            config.scan.offline = true;
            config.scan.analyze_only = true;
            config.scan.skip_analysis = false;
            let report = r3kj4_core::scan(config.scan, RuntimeCapture::default(), cancel).await?;
            print_report(&report, &args.common.format)?;
            Ok(if report.coverage.partial { 3 } else { 0 })
        }
        Command::Beautify { input, out } => {
            let input = std::fs::canonicalize(input)?;
            if input.is_dir() {
                let out = out.context("directory beautification requires --out")?;
                let output = r3kj4_core::output::Output::create(&out)?;
                for entry in walk_sources(&input)? {
                    let text = std::fs::read_to_string(&entry)?;
                    let formatted =
                        r3kj4_core::analysis::beautify(&text, &entry.to_string_lossy())?;
                    let relative = entry
                        .strip_prefix(&input)?
                        .to_string_lossy()
                        .replace('\\', "/");
                    output.write(&format!("formatted/{relative}"), formatted.as_bytes())?;
                }
            } else {
                let text = std::fs::read_to_string(&input)?;
                let formatted = r3kj4_core::analysis::beautify(&text, &input.to_string_lossy())?;
                if let Some(out) = out {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(out)?
                        .write_all(formatted.as_bytes())?;
                } else {
                    io::stdout().lock().write_all(formatted.as_bytes())?;
                }
            }
            Ok(0)
        }
        Command::Doctor {
            browser,
            chrome,
            cdp_url,
        } => {
            let mut result = serde_json::json!({"tool":"r3kj4","version":env!("CARGO_PKG_VERSION"),"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"oxc":"0.154.0","browser_backend":"session-aware CDP"});
            if browser {
                config.browser.chrome = chrome.or(config.browser.chrome);
                config.browser.cdp_url = cdp_url.or(config.browser.cdp_url);
                result["browser"] = r3kj4_browser::doctor(&config.browser, &config.scan).await?;
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(0)
        }
    }
}

fn walk_sources(root: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut files = vec![];
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            files.extend(walk_sources(&entry.path())?);
        } else if kind.is_file() {
            let ext = entry
                .path()
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            if ["js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx"].contains(&ext.as_str()) {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}
fn print_report(report: &ScanReport, format: &Format) -> Result<()> {
    let mut stdout = io::stdout().lock();
    match format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut stdout, report)?;
            writeln!(stdout)?;
        }
        Format::Text => {
            writeln!(
                stdout,
                "{}: {} artifacts, {} sources, {} endpoints, {} findings",
                if report.coverage.partial {
                    "PARTIAL"
                } else {
                    "COMPLETE"
                },
                report.artifacts.len(),
                report.recovered_sources.len(),
                report.endpoints.len(),
                report.findings.len()
            )?;
            for e in &report.endpoints {
                writeln!(
                    stdout,
                    "[{}] {} {} ({})",
                    if e.observed { "observed" } else { "inferred" },
                    e.method,
                    e.url,
                    e.client
                )?;
            }
            for f in &report.findings {
                writeln!(stdout, "[{} / {}] {}", f.rule, f.confidence, f.value)?;
                for e in &f.evidence {
                    writeln!(stdout, "  {}:{}:{}", e.location, e.line, e.column)?;
                }
            }
            writeln!(stdout, "Reports: {}", report.options.out.display())?;
        }
    }
    for d in &report.diagnostics {
        eprintln!("[{}] {}: {}", d.code, d.location, d.message);
    }
    Ok(())
}
