use std::path::PathBuf;

use clap::Parser;

use reticulum_node::{Node, NodeConfig};

#[derive(Parser)]
#[command(name = "reticulum-node", about = "Reticulum mesh network node")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/reticulum/config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging
    if std::env::var("RUST_LOG_FORMAT").as_deref() == Ok("json") {
        reticulum_node::logging::init_json();
    } else {
        reticulum_node::logging::init();
    }

    let config = match NodeConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config from {}: {e}", cli.config.display());
            std::process::exit(1);
        }
    };

    let mut node = Node::new(config);

    // Spawn SIGINT handler
    let handle = node.shutdown_handle();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received SIGINT, shutting down");
        handle.shutdown();
    });

    // Spawn SIGTERM handler (Docker sends SIGTERM on `docker stop`)
    #[cfg(unix)]
    {
        let handle2 = node.shutdown_handle();
        tokio::spawn(async move {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            sigterm.recv().await;
            tracing::info!("received SIGTERM, shutting down");
            handle2.shutdown();
        });
    }

    if let Err(e) = node.start().await {
        tracing::error!("failed to start node: {e}");
        std::process::exit(1);
    }

    node.run().await;
    node.shutdown().await;
}
