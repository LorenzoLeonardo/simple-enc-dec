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
    ParseError = -7,
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
    fn success(result: Cow<'a, str>) -> Self {
        CryptoResult {
            code: Code::Success,
            result: Some(result),
            error: None,
        }
    }

    fn error(code: Code, error: Cow<'a, str>) -> Self {
        CryptoResult {
            code,
            result: None,
            error: Some(error),
        }
    }
}

// Convert CryptoResult into serde_json::Value reliably
impl<'a> From<CryptoResult<'a>> for Value {
    fn from(cr: CryptoResult<'a>) -> Self {
        serde_json::to_value(cr)
            .unwrap_or_else(|e| json!({ "code": Code::ParseError, "error": e.to_string() }))
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
    fn wrap_result<E: ToString>(res: Result<Cow<'_, str>, E>, rc: Code) -> Value {
        match res {
            Ok(s) => CryptoResult::success(s).into(),
            Err(e) => CryptoResult::error(rc, Cow::Borrowed(&e.to_string())).into(),
        }
    }

    /// Base64 decode helper
    fn decode_base64(input: Cow<'_, str>) -> Value {
        log::info!("Decoding base64 input: {input}");
        let res = general_purpose::STANDARD
            .decode(input.as_bytes())
            .map_err(|e| Cow::Owned::<String>(e.to_string()))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map(Cow::Owned)
                    .map_err(|e| Cow::Owned(e.to_string()))
            });

        Self::wrap_result(res, Code::DecodeError)
    }

    /// Base64 encode helper
    fn encode_base64(input: Cow<'_, str>) -> Value {
        log::info!("Encoding base64 input: {input}");
        CryptoResult::success(general_purpose::STANDARD.encode(input.as_bytes()).into()).into()
    }

    /// Require passphrase or return error JSON with caller-provided error code
    fn require_passphrase(passphrase: &str, rc: Code) -> Option<CryptoResult<'_>> {
        if passphrase.is_empty() {
            Some(CryptoResult::error(
                rc,
                Cow::Borrowed("Passphrase is required"),
            ))
        } else {
            None
        }
    }

    /// Base52 decode helper
    fn decode_base52(input: Cow<'_, str>) -> Value {
        log::info!("Decoding base52 input: {input}");
        let codec = Base52Codec;

        let res = codec
            .decode(input)
            .map_err(|e| Cow::Owned::<String>(e.to_string()))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map(Cow::Owned)
                    .map_err(|e| Cow::Owned(e.to_string()))
            });

        Self::wrap_result(res, Code::DecodeError)
    }

    /// Base52 encode helper
    fn encode_base52(input: Cow<'_, str>) -> Value {
        log::info!("Encoding base52 input: {input}");
        let codec = Base52Codec;
        CryptoResult::success(codec.encode(input.as_bytes()).into()).into()
    }
}

#[async_trait]
impl SharedObject for Crypto {
    async fn call(&self, method: &str, args: &Value) -> Value {
        let param: Param = match serde_json::from_value(args.clone()) {
            Ok(p) => p,
            Err(e) => {
                return CryptoResult::error(Code::InvalidArgumentsError, Cow::Owned(e.to_string()))
                    .into();
            }
        };

        match method {
            "decode" => Crypto::decode_base64(param.input),
            "encode" => Crypto::encode_base64(param.input),
            "encrypt" => {
                log::info!("Encrypting input: {}", param.input);
                if let Some(err) = Crypto::require_passphrase(&param.passphrase, Code::EncryptError)
                {
                    return err.into();
                }
                Crypto::wrap_result(encrypt(param.input, param.passphrase), Code::EncryptError)
            }
            "decrypt" => {
                log::info!("Decrypting input: {}", param.input);
                if let Some(err) = Crypto::require_passphrase(&param.passphrase, Code::DecryptError)
                {
                    return err.into();
                }
                Crypto::wrap_result(decrypt(param.input, param.passphrase), Code::DecryptError)
            }
            "decode52" => Crypto::decode_base52(param.input),
            "encode52" => Crypto::encode_base52(param.input),
            "scrypt-encrypt" => {
                log::info!("Encrypting input: {}", param.input);
                if let Some(err) = Crypto::require_passphrase(&param.passphrase, Code::EncryptError)
                {
                    return err.into();
                }
                Crypto::wrap_result(
                    scrypt::encrypt_base64(param.input.as_bytes(), param.passphrase),
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
                    scrypt::decrypt_base64(param.input, param.passphrase)
                        .map_err(|e| Cow::Owned::<String>(e.to_string()))
                        .and_then(|bytes| {
                            String::from_utf8(bytes)
                                .map(Cow::Owned)
                                .map_err(|e| Cow::Owned(e.to_string()))
                        }),
                    Code::DecryptError,
                )
            }
            _ => {
                let msg = format!("Unknown method called: {method}");
                log::warn!("{msg}");
                CryptoResult::error(Code::UnknownMethodError, Cow::Borrowed(&msg)).into()
            }
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use enzo_crypto::base52::Base52Codec;

    #[test]
    fn decode_base64_good() {
        let v = Crypto::decode_base64(std::borrow::Cow::Borrowed("SGVsbG8gd29ybGQ="));
        assert_eq!(v["code"].as_i64().unwrap(), 0);
        assert_eq!(v["result"].as_str().unwrap(), "Hello world");
    }

    #[test]
    fn decode_base64_empty() {
        let v = Crypto::decode_base64(std::borrow::Cow::Borrowed(""));
        assert_eq!(v["code"].as_i64().unwrap(), 0);
        assert_eq!(v["result"].as_str().unwrap(), "");
    }

    #[test]
    fn decode_base64_invalid_base64() {
        let v = Crypto::decode_base64(std::borrow::Cow::Borrowed("!!!!"));
        assert_eq!(v["code"].as_i64().unwrap(), Code::DecodeError as i64);
        assert!(v.get("error").and_then(|e| e.as_str()).is_some());
    }

    #[test]
    fn decode_base64_invalid_utf8() {
        // "/w==" decodes to 0xff which is invalid UTF-8
        let v = Crypto::decode_base64(std::borrow::Cow::Borrowed("/w=="));
        assert_eq!(v["code"].as_i64().unwrap(), Code::DecodeError as i64);
        let err = v["error"].as_str().unwrap();
        assert!(err.contains("invalid utf-8"));
    }

    #[test]
    fn encode_base64_good() {
        let v = Crypto::encode_base64(std::borrow::Cow::Borrowed("hello"));
        assert_eq!(v["code"].as_i64().unwrap(), 0);
        assert_eq!(v["result"].as_str().unwrap(), "aGVsbG8=");
    }

    #[test]
    fn encode_decode_base52_roundtrip() {
        let codec = Base52Codec;
        let src = "The quick brown fox 🦊";
        let encoded = codec.encode(src);
        // encode_base52 should match codec.encode
        let got_enc = Crypto::encode_base52(std::borrow::Cow::Borrowed(src));
        assert_eq!(got_enc["code"].as_i64().unwrap(), 0);
        assert_eq!(got_enc["result"].as_str().unwrap(), encoded);

        // decode_base52 should return original string
        let got_dec = Crypto::decode_base52(std::borrow::Cow::Borrowed(&encoded));
        assert_eq!(got_dec["code"].as_i64().unwrap(), 0);
        assert_eq!(got_dec["result"].as_str().unwrap(), src);
    }

    #[test]
    fn decode_base52_invalid() {
        let v = Crypto::decode_base52(std::borrow::Cow::Borrowed("!!invalid!!"));
        assert_eq!(v["code"].as_i64().unwrap(), Code::DecodeError as i64);
        assert!(v.get("error").and_then(|e| e.as_str()).is_some());
    }

    #[test]
    fn require_passphrase_empty() {
        let r = Crypto::require_passphrase("", Code::EncryptError);
        assert!(r.is_some());
        let cr = r.unwrap();
        // ensure the returned CryptoResult carries the requested code
        match cr.code {
            Code::EncryptError => (),
            other => panic!("expected EncryptError, got {other:?}"),
        }
    }

    #[test]
    fn wrap_result_ok_and_err() {
        // Ok case
        let v = Crypto::wrap_result::<&str>(Ok("fine".into()), Code::EncryptError);
        assert_eq!(v["code"].as_i64().unwrap(), 0);
        assert_eq!(v["result"].as_str().unwrap(), "fine");

        // Err case -> uses provided rc
        let v = Crypto::wrap_result::<&str>(Err("boom"), Code::DecryptError);
        assert_eq!(v["code"].as_i64().unwrap(), Code::DecryptError as i64);
        assert_eq!(v["error"].as_str().unwrap(), "boom");
    }
}
