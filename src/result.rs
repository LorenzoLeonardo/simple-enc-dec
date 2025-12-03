use serde::de::{DeserializeOwned, Error};

pub enum GenericResult<T, E> {
    Ok(T),
    Err(E),
}

impl<T, E> From<GenericResult<T, E>> for serde_json::Value
where
    T: serde::Serialize,
    E: serde::Serialize,
{
    fn from(res: GenericResult<T, E>) -> Self {
        match res {
            GenericResult::Ok(v) => serde_json::json!(v),
            GenericResult::Err(e) => serde_json::json!(e),
        }
    }
}

impl<T, E> TryFrom<serde_json::Value> for GenericResult<T, E>
where
    T: DeserializeOwned,
    E: DeserializeOwned,
{
    type Error = serde_json::Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        // First try to parse T
        if let Ok(v) = serde_json::from_value::<T>(value.clone()) {
            return Ok(GenericResult::Ok(v));
        }

        // Otherwise try E
        if let Ok(e) = serde_json::from_value::<E>(value) {
            return Ok(GenericResult::Err(e));
        }

        // Dynamic type names for error message
        let t_name = std::any::type_name::<T>();
        let e_name = std::any::type_name::<E>();
        // If neither works, return a JSON error
        Err(serde_json::Error::custom(format!(
            "Value could not be parsed as {} or {}",
            t_name, e_name
        )))
    }
}
