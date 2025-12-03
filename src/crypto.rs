use std::borrow::Cow;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose};

use ipc_broker::worker::SharedObject;
use serde_json::Value;
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{base52::Base52Codec, decrypt, encrypt, result::GenericResult, scrypt};

#[repr(i32)]
#[derive(Serialize_repr, Deserialize_repr, Debug, Default)]
pub enum Code {
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
pub struct CryptoOK<'a> {
    code: Code,
    pub result: Cow<'a, str>,
}

impl<'a> CryptoOK<'a> {
    fn new(result: Cow<'a, str>) -> CryptoOK<'a> {
        CryptoOK {
            code: Code::Success,
            result,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct CryptoError<'a> {
    code: Code,
    error: Cow<'a, str>,
}

impl<'a> CryptoError<'a> {
    fn new(code: Code, error: Cow<'a, str>) -> CryptoError<'a> {
        CryptoError { code, error }
    }
}

type CryptoResult<'a> = GenericResult<CryptoOK<'a>, CryptoError<'a>>;

#[derive(serde::Deserialize)]
struct Param<'a> {
    #[serde(default)]
    input: Cow<'a, str>,
    #[serde(default)]
    passphrase: Cow<'a, str>,
}

pub struct Crypto;

impl Crypto {
    /// Require passphrase or return error JSON with caller-provided error code
    fn require_passphrase<'a>(passphrase: Cow<'a, str>, rc: Code) -> Option<CryptoResult<'a>> {
        if passphrase.is_empty() {
            Some(CryptoResult::Err(CryptoError::new(
                rc,
                Cow::Borrowed("Passphrase is required"),
            )))
        } else {
            None
        }
    }

    /// Base64 decode helper
    pub fn decode_base64<'a>(input: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Decoding base64 input: {input}");
        general_purpose::STANDARD
            .decode(input.as_bytes())
            .map_err(|e| Cow::Owned::<String>(e.to_string()))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map(Cow::Owned)
                    .map_err(|e| Cow::Owned(e.to_string()))
            })
            .map(|s| CryptoResult::Ok(CryptoOK::new(s)))
            .unwrap_or_else(|e| {
                CryptoResult::Err(CryptoError::new(
                    Code::DecodeError,
                    Cow::Owned(e.to_string()),
                ))
            })
    }

    /// Base64 encode helper
    pub fn encode_base64<'a>(input: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Encoding base64 input: {input}");
        CryptoResult::Ok(CryptoOK::new(
            general_purpose::STANDARD.encode(input.as_bytes()).into(),
        ))
    }

    /// Base64 decode helper
    pub fn decode_base64_nopad<'a>(input: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Decoding base64 no padding input: {input}");
        general_purpose::STANDARD_NO_PAD
            .decode(input.as_bytes())
            .map_err(|e| Cow::Owned::<String>(e.to_string()))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map(Cow::Owned)
                    .map_err(|e| Cow::Owned(e.to_string()))
            })
            .map(|s| CryptoResult::Ok(CryptoOK::new(s)))
            .unwrap_or_else(|e| {
                CryptoResult::Err(CryptoError::new(
                    Code::DecodeError,
                    Cow::Owned(e.to_string()),
                ))
            })
    }

    /// Base64 encode helper
    pub fn encode_base64_nopad<'a>(input: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Encoding base64 no padding input: {input}");
        CryptoResult::Ok(CryptoOK::new(
            general_purpose::STANDARD_NO_PAD
                .encode(input.as_bytes())
                .into(),
        ))
    }

    /// Base52 decode helper
    pub fn decode_base52<'a>(input: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Decoding base52 input: {input}");
        let codec = Base52Codec;

        codec
            .decode(input.as_bytes())
            .map_err(|e| Cow::Owned::<String>(e.to_string()))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map(Cow::Owned)
                    .map_err(|e| Cow::Owned(e.to_string()))
            })
            .map(|s| CryptoResult::Ok(CryptoOK::new(s)))
            .unwrap_or_else(|e| {
                CryptoResult::Err(CryptoError::new(
                    Code::DecodeError,
                    Cow::Owned(e.to_string()),
                ))
            })
    }

    /// Base52 encode helper
    pub fn encode_base52<'a>(input: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Encoding base52 input: {input}");
        let codec = Base52Codec;
        GenericResult::Ok(CryptoOK::new(codec.encode(input.as_bytes()).into()))
    }

    pub fn encrypt<'a>(input: Cow<'a, str>, passphrase: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Encrypting input with passphrase.");
        if let Some(err) = Crypto::require_passphrase(passphrase.clone(), Code::EncryptError) {
            return err;
        }
        encrypt(input, passphrase.clone())
            .map(|res| CryptoResult::Ok(CryptoOK::new(res)))
            .unwrap_or_else(|e| {
                CryptoResult::Err(CryptoError::new(
                    Code::EncryptError,
                    Cow::Owned(e.to_string()),
                ))
            })
    }

    pub fn decrypt<'a>(input: Cow<'a, str>, passphrase: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Decrypting input with passphrase.");
        if let Some(err) = Crypto::require_passphrase(passphrase.clone(), Code::DecryptError) {
            return err;
        }
        decrypt(input, passphrase)
            .map(|res| CryptoResult::Ok(CryptoOK::new(res)))
            .unwrap_or_else(|e| {
                CryptoResult::Err(CryptoError::new(
                    Code::DecryptError,
                    Cow::Owned(e.to_string()),
                ))
            })
    }

    pub fn scrypt_encrypt<'a>(input: Cow<'a, str>, passphrase: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Encrypting input with scrypt and passphrase.");
        if let Some(err) = Crypto::require_passphrase(passphrase.clone(), Code::EncryptError) {
            return err;
        }

        scrypt::encrypt_base64(input.as_bytes(), passphrase)
            .map(|s| CryptoResult::Ok(CryptoOK::new(s)))
            .map_err(|e| Cow::Owned::<String>(e.to_string()))
            .unwrap_or_else(|e| {
                CryptoResult::Err(CryptoError::new(
                    Code::DecodeError,
                    Cow::Owned(e.to_string()),
                ))
            })
    }

    pub fn scrypt_decrypt<'a>(input: Cow<'a, str>, passphrase: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Decrypting input with scrypt and passphrase.");
        if let Some(err) = Crypto::require_passphrase(passphrase.clone(), Code::DecryptError) {
            return err;
        }

        scrypt::decrypt_base64(input, passphrase)
            .map_err(|e| Cow::Owned::<String>(e.to_string()))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map(Cow::Owned)
                    .map_err(|e| Cow::Owned(e.to_string()))
            })
            .map(|s| CryptoResult::Ok(CryptoOK::new(s)))
            .unwrap_or_else(|e| {
                CryptoResult::Err(CryptoError::new(
                    Code::DecodeError,
                    Cow::Owned(e.to_string()),
                ))
            })
    }
}

#[async_trait]
impl SharedObject for Crypto {
    async fn call(&self, method: &str, args: &Value) -> Value {
        let param: Param = match serde_json::from_value(args.clone()) {
            Ok(p) => p,
            Err(e) => {
                return CryptoResult::Err(CryptoError::new(
                    Code::InvalidArgumentsError,
                    Cow::Owned(e.to_string()),
                ))
                .into();
            }
        };

        match method {
            "decode64" => Crypto::decode_base64(param.input).into(),
            "encode64" => Crypto::encode_base64(param.input).into(),
            "decode64-nopad" => Crypto::decode_base64_nopad(param.input).into(),
            "encode64-nopad" => Crypto::encode_base64_nopad(param.input).into(),
            "encrypt" => Crypto::encrypt(param.input, param.passphrase).into(),
            "decrypt" => Crypto::decrypt(param.input, param.passphrase).into(),
            "decode52" => Crypto::decode_base52(param.input).into(),
            "encode52" => Crypto::encode_base52(param.input).into(),
            "scrypt-encrypt" => Crypto::scrypt_encrypt(param.input, param.passphrase).into(),
            "scrypt-decrypt" => Crypto::scrypt_decrypt(param.input, param.passphrase).into(),
            _ => {
                let msg = format!("Unknown method called: {method}");
                log::warn!("{msg}");
                CryptoResult::Err(CryptoError::new(
                    Code::UnknownMethodError,
                    Cow::Borrowed(&msg),
                ))
                .into()
            }
        }
    }
}
