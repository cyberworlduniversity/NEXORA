//! Capability declarations for trusted, statically registered analysis tools.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolTrust {
    BuiltIn,
    VerifiedExternal,
    Unverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolEffect {
    ReadOnly,
    FilesystemWrite,
    ExternalProcess,
    NetworkAccess,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub tool_id: String,
    pub version: String,
    pub description: String,
    pub trust: ToolTrust,
    pub effects: Vec<ToolEffect>,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    EmptyField(&'static str),
    DuplicateTool(String),
    UntrustedTool(String),
    EffectNotPermitted { tool: String, effect: ToolEffect },
    ToolNotFound(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::DuplicateTool(id) => write!(f, "tool {id} is already registered"),
            Self::UntrustedTool(id) => {
                write!(f, "tool {id} is not trusted by the active registry policy")
            }
            Self::EffectNotPermitted { tool, effect } => {
                write!(f, "tool {tool} requests disallowed effect {effect:?}")
            }
            Self::ToolNotFound(id) => write!(f, "tool {id} is not registered"),
        }
    }
}
impl std::error::Error for RegistryError {}

#[derive(Clone, Debug, Default)]
pub struct RegistryPolicy {
    pub allow_verified_external: bool,
    pub allow_filesystem_write: bool,
    pub allow_external_process: bool,
    pub allow_network: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ToolRegistry {
    tools: BTreeMap<String, ToolDescriptor>,
}

impl ToolRegistry {
    pub fn register(
        &mut self,
        descriptor: ToolDescriptor,
        policy: &RegistryPolicy,
    ) -> Result<(), RegistryError> {
        if descriptor.tool_id.trim().is_empty() {
            return Err(RegistryError::EmptyField("tool_id"));
        }
        if descriptor.version.trim().is_empty() {
            return Err(RegistryError::EmptyField("version"));
        }
        if descriptor.description.trim().is_empty() {
            return Err(RegistryError::EmptyField("description"));
        }
        if self.tools.contains_key(&descriptor.tool_id) {
            return Err(RegistryError::DuplicateTool(descriptor.tool_id));
        }
        if descriptor.trust == ToolTrust::Unverified
            || (descriptor.trust == ToolTrust::VerifiedExternal && !policy.allow_verified_external)
        {
            return Err(RegistryError::UntrustedTool(descriptor.tool_id));
        }
        for effect in &descriptor.effects {
            let permitted = match effect {
                ToolEffect::ReadOnly => true,
                ToolEffect::FilesystemWrite => policy.allow_filesystem_write,
                ToolEffect::ExternalProcess => policy.allow_external_process,
                ToolEffect::NetworkAccess => policy.allow_network,
            };
            if !permitted {
                return Err(RegistryError::EffectNotPermitted {
                    tool: descriptor.tool_id.clone(),
                    effect: *effect,
                });
            }
        }
        self.tools.insert(descriptor.tool_id.clone(), descriptor);
        Ok(())
    }

    pub fn get(&self, tool_id: &str) -> Result<&ToolDescriptor, RegistryError> {
        self.tools
            .get(tool_id)
            .ok_or_else(|| RegistryError::ToolNotFound(tool_id.to_owned()))
    }

    pub fn list(&self) -> Vec<&ToolDescriptor> {
        self.tools.values().collect()
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(effect: ToolEffect) -> ToolDescriptor {
        ToolDescriptor {
            tool_id: "inspect.header".into(),
            version: "1.0.0".into(),
            description: "Read-only header inspection".into(),
            trust: ToolTrust::BuiltIn,
            effects: vec![effect],
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
        }
    }

    #[test]
    fn default_policy_accepts_only_read_only_builtin_tools() {
        let mut registry = ToolRegistry::default();
        assert!(registry
            .register(descriptor(ToolEffect::ReadOnly), &RegistryPolicy::default())
            .is_ok());
        assert_eq!(registry.len(), 1);
        let mut network_tool = descriptor(ToolEffect::NetworkAccess);
        network_tool.tool_id = "network.inspect".into();
        assert!(matches!(
            registry.register(network_tool, &RegistryPolicy::default()),
            Err(RegistryError::EffectNotPermitted { .. })
        ));
    }

    #[test]
    fn blocks_external_process_without_explicit_policy() {
        let mut registry = ToolRegistry::default();
        let mut value = descriptor(ToolEffect::ExternalProcess);
        value.tool_id = "external.ghidra".into();
        assert!(matches!(
            registry.register(value, &RegistryPolicy::default()),
            Err(RegistryError::EffectNotPermitted { .. })
        ));
    }

    #[test]
    fn blocks_unverified_tools() {
        let mut registry = ToolRegistry::default();
        let mut value = descriptor(ToolEffect::ReadOnly);
        value.trust = ToolTrust::Unverified;
        assert!(matches!(
            registry.register(value, &RegistryPolicy::default()),
            Err(RegistryError::UntrustedTool(_))
        ));
    }
}
