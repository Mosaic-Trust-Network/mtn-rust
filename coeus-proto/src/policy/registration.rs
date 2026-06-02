use super::*;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub enum RegistrationPolicy {
    #[default]
    Owner,
    Any,
}

impl RegistrationPolicy {
    pub fn any() -> Self {
        Self::Any
    }

    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}
