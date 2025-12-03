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
