use std::{borrow::Cow, path::Path};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose};
use chrono::Local;
use enzo_crypto::{base52::Base52Codec, decrypt, encrypt, scrypt};
use fern::Dispatch;
use ipc_broker::worker::{SharedObject, WorkerBuilder};
use log::LevelFilter;
use serde_json::{Value, json};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[repr(i32)]
#[derive(Serialize_repr, Deserialize_repr, Debug, Default)]
enum Code {
    #[default]
    Success = 0,
    DecryptError = -1,
    EncryptError = -2,
    DecodeError = -3,
    EncodeError = -4,
    UnknownMethodError = -5,
    InvalidArgumentsError = -6,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CryptoResult<'a> {
    code: Code,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Cow<'a, str>>,
}

impl<'a> CryptoResult<'a> {
    fn success(result: String) -> Self {
        CryptoResult {
            code: Code::Success,
            result: Some(Cow::Owned(result.to_owned())),
            error: None,
        }
    }

    fn error(code: Code, error: String) -> Self {
        CryptoResult {
            code,
            result: None,
            error: Some(Cow::Owned(error.to_owned())),
        }
    }
}

// Convert CryptoResult into serde_json::Value reliably
impl<'a> From<CryptoResult<'a>> for Value {
    fn from(cr: CryptoResult<'a>) -> Self {
        serde_json::to_value(cr).unwrap_or_else(
            |e| json!({ "error": format!("Failed to serialize CryptoResult: {}", e) }),
        )
    }
}

#[derive(serde::Deserialize)]
struct Param<'a> {
    #[serde(default)]
    input: Cow<'a, str>,
    #[serde(default)]
    passphrase: Cow<'a, str>,
}

struct Crypto;

impl Crypto {
    /// Wrap Ok(String) or Err(E) into a JSON result with the provided error code.
    fn wrap_result<E: ToString>(res: Result<String, E>, rc: Code) -> Value {
        match res {
            Ok(s) => CryptoResult::success(s).into(),
            Err(e) => CryptoResult::error(rc, e.to_string()).into(),
        }
    }

    /// Base64 decode helper
    fn decode_base64(input: &str) -> Value {
        log::info!("Decoding base64 input: {input}");
        let res = general_purpose::STANDARD
            .decode(input)
            .map_err(|e| e.to_string())
            .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string()));

        Self::wrap_result(res, Code::DecodeError)
    }

    /// Base64 encode helper
    fn encode_base64(input: &str) -> Value {
        log::info!("Encoding base64 input: {input}");
        CryptoResult::success(general_purpose::STANDARD.encode(input)).into()
    }

    /// Require passphrase or return error JSON with caller-provided error code
    fn require_passphrase(passphrase: &str, rc: Code) -> Option<CryptoResult> {
        if passphrase.is_empty() {
            Some(CryptoResult::error(
                rc,
                "Passphrase is required".to_string(),
            ))
        } else {
            None
        }
    }

    /// Base52 decode helper
    fn decode_base52(input: &str) -> Value {
        log::info!("Decoding base52 input: {input}");
        let codec = Base52Codec;

        let res = codec
            .decode(input)
            .map_err(|e| e.to_string())
            .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string()));

        Self::wrap_result(res, Code::DecodeError)
    }

    /// Base52 encode helper
    fn encode_base52(input: &str) -> Value {
        log::info!("Encoding base52 input: {input}");
        let codec = Base52Codec;
        CryptoResult::success(codec.encode(input)).into()
    }
}

#[async_trait]
impl SharedObject for Crypto {
    async fn call(&self, method: &str, args: &Value) -> Value {
        let param: Param = match serde_json::from_value(args.clone()) {
            Ok(p) => p,
            Err(e) => {
                return CryptoResult::error(Code::InvalidArgumentsError, e.to_string()).into();
            }
        };

        match method {
            "decode" => Crypto::decode_base64(&param.input),
            "encode" => Crypto::encode_base64(&param.input),
            "encrypt" => {
                log::info!("Encrypting input: {}", param.input);
                if let Some(err) = Crypto::require_passphrase(&param.passphrase, Code::EncryptError)
                {
                    return err.into();
                }
                Crypto::wrap_result(encrypt(&param.input, &param.passphrase), Code::EncryptError)
            }
            "decrypt" => {
                log::info!("Decrypting input: {}", param.input);
                if let Some(err) = Crypto::require_passphrase(&param.passphrase, Code::DecryptError)
                {
                    return err.into();
                }
                Crypto::wrap_result(decrypt(&param.input, &param.passphrase), Code::DecryptError)
            }
            "decode52" => Crypto::decode_base52(&param.input),
            "encode52" => Crypto::encode_base52(&param.input),
            "scrypt-encrypt" => {
                log::info!("Encrypting input: {}", param.input);
                if let Some(err) = Crypto::require_passphrase(&param.passphrase, Code::EncryptError)
                {
                    return err.into();
                }
                Crypto::wrap_result(
                    scrypt::encrypt_base64(param.input.as_bytes(), &param.passphrase),
                    Code::EncryptError,
                )
            }
            "scrypt-decrypt" => {
                log::info!("Decrypting input: {}", param.input);
                if let Some(err) = Crypto::require_passphrase(&param.passphrase, Code::DecryptError)
                {
                    return err.into();
                }
                Crypto::wrap_result(
                    scrypt::decrypt_base64(&param.input, &param.passphrase)
                        .map_err(|e| e.to_string())
                        .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string())),
                    Code::DecryptError,
                )
            }
            _ => {
                let msg = format!("Unknown method called: {method}");
                log::warn!("{msg}");
                CryptoResult::error(Code::UnknownMethodError, msg).into()
            }
        }
    }
}

fn setup_logger() {
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
}

// replace broken tail with a proper async main
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup_logger();

    WorkerBuilder::new()
        .add("applications.crypto", Crypto)
        .spawn()
        .await?;

    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    eprintln!("{name} {version} has ended...");

    Ok(())
}
