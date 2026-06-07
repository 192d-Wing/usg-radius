//! State backend configuration

use serde::{Deserialize, Serialize};

/// Type of state backend to use
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StateBackendType {
    /// In-memory state backend (default)
    #[default]
    InMemory,
}

/// Configuration for state backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateConfig {
    /// Backend type to use
    #[serde(default)]
    pub backend: StateBackendType,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            backend: StateBackendType::InMemory,
        }
    }
}

impl StateConfig {
    /// Create a new in-memory state configuration
    pub fn in_memory() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_state_config() {
        let config = StateConfig::default();
        assert_eq!(config.backend, StateBackendType::InMemory);
    }

    #[test]
    fn test_in_memory_config() {
        let config = StateConfig::in_memory();
        assert_eq!(config.backend, StateBackendType::InMemory);
    }

    #[test]
    fn test_serde_in_memory() {
        let config = StateConfig::in_memory();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: StateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.backend, StateBackendType::InMemory);
    }
}
