use std::path::Path;

use chrono::Local;
use enzo_crypto::crypto::Crypto;
use fern::Dispatch;
use ipc_broker::worker::WorkerBuilder;
use log::LevelFilter;

struct LogHandler;

impl LogHandler {
    fn start() -> Self {
        let level_filter = match (Path::new("trace").exists(), Path::new("debug").exists()) {
            (true, true) | (true, false) => LevelFilter::Trace,
            (false, true) => LevelFilter::Debug,
            (false, false) => LevelFilter::Info, // Default level
        };

        if let Err(e) = Dispatch::new()
            .format(move |out, message, record| {
                let file = record.file().unwrap_or("unknown_file");
                let line = record.line().map_or(0, |l| l);

                match level_filter {
                    LevelFilter::Off
                    | LevelFilter::Error
                    | LevelFilter::Warn
                    | LevelFilter::Debug
                    | LevelFilter::Trace => {
                        out.finish(format_args!(
                            "[{}][{}]: {} <{}:{}>",
                            Local::now().format("%b-%d-%Y %H:%M:%S.%f"),
                            record.level(),
                            message,
                            file,
                            line,
                        ));
                    }
                    LevelFilter::Info => {
                        out.finish(format_args!(
                            "[{}]: {} <{}:{}>",
                            record.level(),
                            message,
                            file,
                            line,
                        ));
                    }
                }
            })
            .level(level_filter)
            .chain(std::io::stdout())
            .apply()
        {
            log::error!("Logger initialization failed: {e:?}");
        }
        let name = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");
        log::info!("{name} {version} has started...");
        Self
    }
}
impl Drop for LogHandler {
    fn drop(&mut self) {
        let name = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");
        log::info!("{name} {version} has ended...");
        log::logger().flush();
    }
}
// replace broken tail with a proper async main
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let logger = LogHandler::start();

    WorkerBuilder::new()
        .add("applications.crypto", Crypto)
        .spawn()
        .await?;

    drop(logger);
    Ok(())
}
