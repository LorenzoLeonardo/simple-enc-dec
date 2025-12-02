use std::borrow::Cow;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose};

use ipc_broker::worker::SharedObject;
use serde_json::Value;
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    base52::Base52Codec,
    decrypt, encrypt,
    result::{DefaultFallback, GenericResult},
    scrypt,
};

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
    fn success(result: Cow<'a, str>) -> Self {
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
    fn error(code: Code, error: Cow<'a, str>) -> Self {
        CryptoError { code, error }
    }
}

type CryptoResult<'a> = GenericResult<CryptoOK<'a>, CryptoError<'a>, DefaultFallback>;

#[derive(serde::Deserialize)]
struct Param<'a> {
    #[serde(default)]
    input: Cow<'a, str>,
    #[serde(default)]
    passphrase: Cow<'a, str>,
}

pub struct Crypto;

impl Crypto {
    /// Wrap Ok(String) or Err(E) into a JSON result with the provided error code.
    fn wrap_result<'a, E: ToString>(res: Result<Cow<'a, str>, E>, rc: Code) -> CryptoResult<'a> {
        match res {
            Ok(s) => CryptoResult::ok(CryptoOK::success(s)),
            Err(e) => CryptoResult::err(CryptoError::error(rc, Cow::Owned(e.to_string()))),
        }
    }

    /// Require passphrase or return error JSON with caller-provided error code
    fn require_passphrase<'a>(passphrase: Cow<'a, str>, rc: Code) -> Option<CryptoResult<'a>> {
        if passphrase.is_empty() {
            Some(CryptoResult::err(CryptoError::error(
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
    pub fn encode_base64<'a>(input: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Encoding base64 input: {input}");
        CryptoResult::ok(CryptoOK::success(
            general_purpose::STANDARD.encode(input.as_bytes()).into(),
        ))
    }

    /// Base64 decode helper
    pub fn decode_base64_nopad<'a>(input: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Decoding base64 no padding input: {input}");
        let res = general_purpose::STANDARD_NO_PAD
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
    pub fn encode_base64_nopad<'a>(input: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Encoding base64 no padding input: {input}");
        GenericResult::ok(CryptoOK::success(
            general_purpose::STANDARD_NO_PAD
                .encode(input.as_bytes())
                .into(),
        ))
    }

    /// Base52 decode helper
    pub fn decode_base52<'a>(input: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Decoding base52 input: {input}");
        let codec = Base52Codec;

        let res = codec
            .decode(input.as_bytes())
            .map_err(|e| Cow::Owned::<String>(e.to_string()))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map(Cow::Owned)
                    .map_err(|e| Cow::Owned(e.to_string()))
            });

        Self::wrap_result(res, Code::DecodeError)
    }

    /// Base52 encode helper
    pub fn encode_base52<'a>(input: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Encoding base52 input: {input}");
        let codec = Base52Codec;
        GenericResult::ok(CryptoOK::success(codec.encode(input.as_bytes()).into()))
    }

    pub fn encrypt<'a>(input: Cow<'a, str>, passphrase: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Encrypting input with passphrase.");
        if let Some(err) = Crypto::require_passphrase(passphrase.clone(), Code::EncryptError) {
            return err;
        }
        Self::wrap_result(encrypt(input, passphrase.clone()), Code::EncryptError)
    }

    pub fn decrypt<'a>(input: Cow<'a, str>, passphrase: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Decrypting input with passphrase.");
        if let Some(err) = Crypto::require_passphrase(passphrase.clone(), Code::DecryptError) {
            return err;
        }
        Self::wrap_result(decrypt(input, passphrase), Code::DecryptError)
    }

    pub fn scrypt_encrypt<'a>(input: Cow<'a, str>, passphrase: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Encrypting input with scrypt and passphrase.");
        if let Some(err) = Crypto::require_passphrase(passphrase.clone(), Code::EncryptError) {
            return err;
        }
        Crypto::wrap_result(
            scrypt::encrypt_base64(input.as_bytes(), passphrase),
            Code::EncryptError,
        )
    }

    pub fn scrypt_decrypt<'a>(input: Cow<'a, str>, passphrase: Cow<'a, str>) -> CryptoResult<'a> {
        log::info!("Decrypting input with scrypt and passphrase.");
        if let Some(err) = Crypto::require_passphrase(passphrase.clone(), Code::DecryptError) {
            return err;
        }
        Crypto::wrap_result(
            scrypt::decrypt_base64(input, passphrase)
                .map_err(|e| Cow::Owned::<String>(e.to_string()))
                .and_then(|bytes| {
                    String::from_utf8(bytes)
                        .map(Cow::Owned)
                        .map_err(|e| Cow::Owned(e.to_string()))
                }),
            Code::DecryptError,
        )
    }
}

#[async_trait]
impl SharedObject for Crypto {
    async fn call(&self, method: &str, args: &Value) -> Value {
        let param: Param = match serde_json::from_value(args.clone()) {
            Ok(p) => p,
            Err(e) => {
                return CryptoResult::err(CryptoError::error(
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
                CryptoResult::err(CryptoError::error(
                    Code::UnknownMethodError,
                    Cow::Borrowed(&msg),
                ))
                .into()
            }
        }
    }
}
