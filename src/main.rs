use std::{
    collections::HashSet,
    ops::ControlFlow,
    path::{Path, MAIN_SEPARATOR},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc
    },
    time::{Duration, Instant}
};

use anyhow::Error;
use clap::Parser;
use indexmap::IndexSet;
use lazy_static::lazy_static;
use log::{error, info};
use rand::random;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::Mutex,
    time::sleep
};
use xelis_common::{
    async_handler,
    config::XELIS_ASSET,
    crypto::{
        ecdlp,
        Address,
        Hashable,
        KeyPair,
        PublicKey
    },
    network::Network,
    prompt::{
        default_logs_datetime_format, is_maybe_dir,
        Color,
        LogLevel,
        ModuleConfig,
        Prompt
    },
    tokio::spawn_task,
    transaction::builder::{
        FeeBuilder,
        TransactionTypeBuilder,
        TransferBuilder
    },
    utils::{format_hashrate, format_xelis}
};
use xelis_wallet::{
    config::{
        PrecomputedTablesConfig,
        DEFAULT_DAEMON_ADDRESS
    },
    daemon_api::DaemonAPI,
    precomputed_tables,
    wallet::Wallet
};

// Functions helpers for serde default values
fn default_filename_log() -> String {
    "xelis-storm.log".to_owned()
}

fn default_logs_path() -> String {
    "logs/".to_owned()
}

fn default_wallets_dir() -> String {
    "wallets/".to_string()
}

fn default_daemon_address() -> String {
    DEFAULT_DAEMON_ADDRESS.to_owned()
}

fn default_wallets_count() -> usize {
    1
}

#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
pub struct LogConfig {
    /// Set log level
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    #[serde(default)]
    log_level: LogLevel,
    /// Set file log level
    /// By default, it will be the same as log level
    #[clap(long, value_enum)]
    file_log_level: Option<LogLevel>,
    /// Disable the log file
    #[clap(long)]
    #[serde(default)]
    disable_file_logging: bool,
    /// Disable the log filename date based
    /// If disabled, the log file will be named xelis-daemon.log instead of YYYY-MM-DD.xelis-daemon.log
    #[clap(long)]
    #[serde(default)]
    disable_file_log_date_based: bool,
    /// Disable the usage of colors in log
    #[clap(long)]
    #[serde(default)]
    disable_log_color: bool,
    /// Disable terminal interactive mode
    /// You will not be able to write CLI commands in it or to have an updated prompt
    #[clap(long)]
    #[serde(default)]
    disable_interactive_mode: bool,
    /// Enable the log file auto compression
    /// If enabled, the log file will be compressed every day
    /// This will only work if the log file is enabled
    #[clap(long)]
    #[serde(default)]
    auto_compress_logs: bool,
    /// Log filename
    /// 
    /// By default filename is xelis-daemon.log.
    /// File will be stored in logs directory, this is only the filename, not the full path.
    /// Log file is rotated every day and has the format YYYY-MM-DD.xelis-daemon.log.
    #[clap(long, default_value_t = default_filename_log())]
    #[serde(default = "default_filename_log")]
    filename_log: String,
    /// Logs directory
    /// 
    /// By default it will be logs/ of the current directory.
    /// It must end with a / to be a valid folder.
    #[clap(long, default_value_t = default_logs_path())]
    #[serde(default = "default_logs_path")]
    logs_path: String,
    /// Module configuration for logs
    #[clap(long)]
    #[serde(default)]
    logs_modules: Vec<ModuleConfig>,
    /// Disable the ascii art at startup
    #[clap(long)]
    #[serde(default)]
    disable_ascii_art: bool,
    /// Change the datetime format used by the logger
    #[clap(long, default_value_t = default_logs_datetime_format())]
    #[serde(default = "default_logs_datetime_format")]
    datetime_format: String, 
}

#[derive(Debug, Parser, Serialize, Deserialize)]
pub struct Config {
    #[clap(flatten)]
    log: LogConfig,
    // How many wallets do we want
    #[clap(long, default_value_t = default_wallets_count())]
    #[serde(default = "default_wallets_count")]
    from_n_wallets: usize,
    #[clap(long, default_value_t = default_wallets_dir())]
    wallets_dir: String,
    #[clap(long, default_value_t = Network::Testnet)]
    network: Network,
    /// Precopmuted tables configuration
    #[clap(flatten)]
    precomputed_tables: PrecomputedTablesConfig,
    #[clap(long, default_value_t = default_daemon_address())]
    #[serde(default = "default_daemon_address")]
    daemon_address: String,
    #[clap(long)]
    fixed_transfers_count: Option<u8>,
    #[clap(long)]
    fixed_transfer_receiver_address: Option<Address>,
    #[clap(long)]
    #[serde(default)]
    show_wallets_only: bool,
}

/// This struct is used to log the progress of the table generation
struct LogProgressTableGenerationReportFunction;

impl ecdlp::ProgressTableGenerationReportFunction for LogProgressTableGenerationReportFunction {
    fn report(&self, progress: f64, step: ecdlp::ReportStep) -> ControlFlow<()> {
        info!("Progress: {:.2}% on step {:?}", progress * 100.0, step);
        ControlFlow::Continue(())
    }
}

static HASHRATE_COUNTER: AtomicUsize = AtomicUsize::new(0);
lazy_static! {
    static ref HASHRATE_LAST_TIME: Mutex<Instant> = Mutex::new(Instant::now());
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut config = Config::parse();
    if !is_maybe_dir(&config.wallets_dir) {
        config.wallets_dir.push(MAIN_SEPARATOR);
    }

    let log_config = config.log;
    let prompt = Prompt::new(
        log_config.log_level,
        &log_config.logs_path,
        &log_config.filename_log,
        log_config.disable_file_logging,
        log_config.disable_file_log_date_based,
        log_config.disable_log_color,
        log_config.auto_compress_logs,
        !log_config.disable_interactive_mode,
        log_config.logs_modules.clone(),
        log_config.file_log_level.unwrap_or(log_config.log_level),
        !log_config.disable_ascii_art,
        log_config.datetime_format.clone(),
    )?;

    let precomputed_tables = precomputed_tables::read_or_generate_precomputed_tables(
        config.precomputed_tables.precomputed_tables_path.as_deref(),
        config.precomputed_tables.precomputed_tables_l1,
        LogProgressTableGenerationReportFunction,
        true
    ).await?;

    let mut wallets = Vec::with_capacity(config.from_n_wallets);
    let mut keys = IndexSet::with_capacity(config.from_n_wallets);

    let api = Arc::new(DaemonAPI::new(format!("{}/json_rpc", config.daemon_address)).await?);
    for i in 0..config.from_n_wallets {
        let name = format!("{}storm-#{}", config.wallets_dir, i);
        let wallet = if Path::new(&name).exists() {
            info!("Opening existing wallet {}", name);
            Wallet::open(&name, "", config.network, precomputed_tables.clone(), 1, 8)?
        } else {
            info!("Creating existing wallet {}", name);
            Wallet::create(&name, "", None, config.network, precomputed_tables.clone(), 1, 8).await?
        };

        wallet.set_online_mode_with_api(api.clone(), true).await?;
        wallet.set_history_scan(false);

        let addr = wallet.get_address();
        info!("Wallet #{}: {}", i, addr);
        if let Some(network_handler) = wallet.get_network_handler().lock().await.as_ref() {
            network_handler.sync_head_state(&addr, Some(HashSet::from_iter([XELIS_ASSET])), None, true, true).await?;
        }

        keys.insert(wallet.get_public_key().clone());
        wallets.push(wallet);
    }

    if config.show_wallets_only {
        for (i, wallet) in wallets.iter().enumerate() {
            let storage = wallet.get_storage().read().await;
            let balance = storage.get_plaintext_balance_for(&XELIS_ASSET).await.unwrap_or(0);
            info!("Wallet #{}: {}", i, format_xelis(balance));
        }

        return Ok(())
    }

    let handles = wallets.into_iter().enumerate().map(|(i, wallet)| {
        let mut keys = keys.clone();
        keys.swap_remove(wallet.get_public_key());

        spawn_task(format!("wallet-#{}", i), generate_txs(
            i,
            wallet,
            keys,
            config.fixed_transfers_count,
            config.fixed_transfer_receiver_address.clone(),
        ))
    }).collect::<Vec<_>>();

    let closure = |_: &_, _: _| async {
        let wallets_str = format!(
            "{}: {}",
            prompt.colorize_string(Color::Yellow, "Wallets"),
            prompt.colorize_string(Color::Green, &format!("{}", config.from_n_wallets)),
        );
        let hashrate = {
            let mut last_time = HASHRATE_LAST_TIME.lock().await;
            let counter = HASHRATE_COUNTER.swap(0, Ordering::SeqCst);

            let hashrate = 1000f64 / (last_time.elapsed().as_millis() as f64 / counter as f64);
            *last_time = Instant::now();

            prompt.colorize_string(Color::Green, &format!("{}", format_hashrate(hashrate)))
        };

        Ok(
            format!(
                "{} | {} | {} {} ",
                prompt.colorize_string(Color::Blue, "XELIS Storm"),
                wallets_str,
                hashrate,
                prompt.colorize_string(Color::BrightBlack, ">>")
            )
        )
    };

    prompt.start(Duration::from_secs(1), Box::new(async_handler!(closure)), None).await?;

    for handle in handles {
        handle.abort();
    }

    Ok(())
}

pub async fn generate_txs(i: usize, wallet: Arc<Wallet>, keys: IndexSet<PublicKey>, fixed_transfers_count: Option<u8>, default_transfer_address: Option<Address>) {
    loop {
        let transfers_count = fixed_transfers_count.unwrap_or_else(|| random::<u8>().max(1));
        let transfers = (0..transfers_count).map(|_| {
            let destination = if keys.is_empty() {
                if let Some(address) = default_transfer_address.as_ref() {
                    address.get_public_key().clone()
                } else {
                    KeyPair::new().get_public_key().compress()
                }
            } else {
                let index = random::<u8>() as usize % keys.len();
                keys.get_index(index)
                    .expect("key at index") 
                    .clone()
            }.as_address(wallet.get_network().is_mainnet());

            TransferBuilder {
                amount: 0,
                destination,
                extra_data: None,
                asset: XELIS_ASSET,
                encrypt_extra_data: true
            }
        }).collect();

        let res = wallet.create_transaction(TransactionTypeBuilder::Transfers(transfers), FeeBuilder::Boost(0)).await;
        HASHRATE_COUNTER.fetch_add(1, Ordering::SeqCst);

        match res {
            Ok(tx) => {
                let start = Instant::now();
                if let Err(e) = wallet.submit_transaction(&tx).await {
                    error!("Error on submit from wallet #{}: {}", i, e);
                    let mut storage = wallet.get_storage().write().await;
                    storage.clear_tx_cache();
                    storage.delete_unconfirmed_balances().await;
                } else {
                    info!("TX {} submitted from wallet #{} in {:?}", tx.hash(), i, start.elapsed());
                }
            }
            Err(e) => {
                error!("Error while building TX on wallet #{}: {}", i, e);
                {
                    let mut storage = wallet.get_storage().write().await;
                    storage.clear_tx_cache();
                    storage.delete_unconfirmed_balances().await;
                }

                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}