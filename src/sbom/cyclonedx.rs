//! CycloneDX 1.5 SBOM output format.

use super::builder::Component;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// CycloneDX 1.5 BOM structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxBom {
    /// BOM format (always "CycloneDX")
    pub bom_format: String,

    /// Spec version
    pub spec_version: String,

    /// Serial number (UUID)
    pub serial_number: String,

    /// BOM version
    pub version: i32,

    /// Metadata about the BOM
    pub metadata: CycloneDxMetadata,

    /// Components in the BOM
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<CycloneDxComponent>,

    /// Services in the BOM (MCP servers)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<CycloneDxService>,
}

/// Metadata about the BOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxMetadata {
    /// Timestamp of generation
    pub timestamp: String,

    /// Tools used to generate the BOM
    pub tools: Vec<CycloneDxTool>,
}

/// Tool information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxTool {
    /// Vendor name
    pub vendor: String,

    /// Tool name
    pub name: String,

    /// Tool version
    pub version: String,
}

/// A component in the CycloneDX BOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxComponent {
    /// Component type
    #[serde(rename = "type")]
    pub component_type: String,

    /// BOM reference (unique ID)
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,

    /// Component name
    pub name: String,

    /// Component version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Package URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,

    /// Publisher
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,

    /// Licenses
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub licenses: Vec<CycloneDxLicense>,

    /// External references
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<CycloneDxExternalRef>,

    /// Hashes
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<CycloneDxHash>,
}

/// A service in the CycloneDX BOM (for MCP servers).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxService {
    /// BOM reference (unique ID)
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,

    /// Service name
    pub name: String,

    /// Service version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Provider information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<CycloneDxProvider>,

    /// External references
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<CycloneDxExternalRef>,
}

/// Provider information for a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxProvider {
    /// Provider name
    pub name: String,
}

/// License information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxLicense {
    /// License container
    pub license: CycloneDxLicenseInfo,
}

/// License details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxLicenseInfo {
    /// SPDX license ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// License name (if not SPDX)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// External reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxExternalRef {
    /// Reference type
    #[serde(rename = "type")]
    pub ref_type: String,

    /// URL
    pub url: String,
}

/// Hash information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxHash {
    /// Algorithm
    pub alg: String,

    /// Hash content
    pub content: String,
}

impl CycloneDxBom {
    /// Create a new BOM from components.
    pub fn from_components(components: &[Component]) -> Self {
        let mut cyclone_components = Vec::new();
        let mut services = Vec::new();

        for comp in components {
            match comp.component_type {
                super::builder::ComponentType::McpServer
                | super::builder::ComponentType::Service => {
                    services.push(CycloneDxService::from_component(comp));
                }
                _ => {
                    cyclone_components.push(CycloneDxComponent::from_component(comp));
                }
            }
        }

        Self {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            version: 1,
            metadata: CycloneDxMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                tools: vec![CycloneDxTool {
                    vendor: "Anthropic".to_string(),
                    name: "cc-audit".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                }],
            },
            components: cyclone_components,
            services,
        }
    }
}

impl CycloneDxComponent {
    /// Create from a Component.
    fn from_component(comp: &Component) -> Self {
        let bom_ref = format!(
            "{}@{}",
            comp.name,
            comp.version.as_deref().unwrap_or("unversioned")
        );

        let mut licenses = Vec::new();
        if let Some(ref license) = comp.license {
            licenses.push(CycloneDxLicense {
                license: CycloneDxLicenseInfo {
                    id: Some(license.clone()),
                    name: None,
                },
            });
        }

        let mut external_refs = Vec::new();
        if let Some(ref repo) = comp.repository {
            external_refs.push(CycloneDxExternalRef {
                ref_type: "vcs".to_string(),
                url: repo.clone(),
            });
        }

        let mut hashes = Vec::new();
        if let Some(ref hash) = comp.hash_sha256 {
            hashes.push(CycloneDxHash {
                alg: "SHA-256".to_string(),
                content: hash.clone(),
            });
        }

        Self {
            component_type: comp.component_type.to_cyclonedx_type().to_string(),
            bom_ref,
            name: comp.name.clone(),
            version: comp.version.clone(),
            description: comp.description.clone(),
            purl: comp.purl.clone(),
            publisher: comp.author.clone(),
            licenses,
            external_references: external_refs,
            hashes,
        }
    }
}

impl CycloneDxService {
    /// Create from a Component.
    fn from_component(comp: &Component) -> Self {
        let bom_ref = format!(
            "service:{}@{}",
            comp.name,
            comp.version.as_deref().unwrap_or("unversioned")
        );

        let mut external_refs = Vec::new();
        if let Some(ref repo) = comp.repository {
            external_refs.push(CycloneDxExternalRef {
                ref_type: "vcs".to_string(),
                url: repo.clone(),
            });
        }

        let provider = comp
            .author
            .as_ref()
            .map(|a| CycloneDxProvider { name: a.clone() });

        Self {
            bom_ref,
            name: comp.name.clone(),
            version: comp.version.clone(),
            description: comp.description.clone(),
            provider,
            external_references: external_refs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom::builder::ComponentType;

    #[test]
    fn test_bom_creation() {
        let components = vec![
            Component::new("test-lib", ComponentType::Library).with_version("1.0.0"),
            Component::new("test-mcp", ComponentType::McpServer).with_version("2.0.0"),
        ];

        let bom = CycloneDxBom::from_components(&components);

        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.5");
        assert_eq!(bom.components.len(), 1);
        assert_eq!(bom.services.len(), 1);
    }

    #[test]
    fn test_component_conversion() {
        let comp = Component::new("my-package", ComponentType::Library)
            .with_version("1.2.3")
            .with_description("A test package")
            .with_license("MIT")
            .with_repository("https://github.com/test/repo");

        let cyclone_comp = CycloneDxComponent::from_component(&comp);

        assert_eq!(cyclone_comp.name, "my-package");
        assert_eq!(cyclone_comp.version, Some("1.2.3".to_string()));
        assert_eq!(cyclone_comp.component_type, "library");
        assert_eq!(cyclone_comp.licenses.len(), 1);
        assert_eq!(cyclone_comp.external_references.len(), 1);
    }

    #[test]
    fn test_service_conversion() {
        let comp = Component::new("my-mcp-server", ComponentType::McpServer)
            .with_version("1.0.0")
            .with_author("Test Author");

        let service = CycloneDxService::from_component(&comp);

        assert_eq!(service.name, "my-mcp-server");
        assert!(service.provider.is_some());
        assert_eq!(service.provider.unwrap().name, "Test Author");
    }

    #[test]
    fn test_json_serialization() {
        let components = vec![Component::new("test", ComponentType::Library)];
        let bom = CycloneDxBom::from_components(&components);

        let json = serde_json::to_string_pretty(&bom).unwrap();

        assert!(json.contains("CycloneDX"));
        assert!(json.contains("1.5"));
        assert!(json.contains("test"));
    }

    #[test]
    fn test_service_type_conversion() {
        // Service type should also go to services
        let components =
            vec![Component::new("my-service", ComponentType::Service).with_version("1.0.0")];

        let bom = CycloneDxBom::from_components(&components);

        assert_eq!(bom.components.len(), 0);
        assert_eq!(bom.services.len(), 1);
    }

    #[test]
    fn test_component_without_version() {
        let comp = Component::new("unversioned-lib", ComponentType::Library);
        let cyclone_comp = CycloneDxComponent::from_component(&comp);

        assert!(cyclone_comp.bom_ref.contains("unversioned"));
        assert!(cyclone_comp.version.is_none());
    }

    #[test]
    fn test_component_with_hash() {
        let comp =
            Component::new("hashed-lib", ComponentType::Library).with_hash("abcdef1234567890");

        let cyclone_comp = CycloneDxComponent::from_component(&comp);

        assert_eq!(cyclone_comp.hashes.len(), 1);
        assert_eq!(cyclone_comp.hashes[0].alg, "SHA-256");
        assert_eq!(cyclone_comp.hashes[0].content, "abcdef1234567890");
    }

    #[test]
    fn test_component_with_purl() {
        let comp =
            Component::new("npm-lib", ComponentType::Library).with_purl("pkg:npm/express@4.18.0");

        let cyclone_comp = CycloneDxComponent::from_component(&comp);

        assert_eq!(
            cyclone_comp.purl,
            Some("pkg:npm/express@4.18.0".to_string())
        );
    }

    #[test]
    fn test_component_with_author() {
        let comp =
            Component::new("authored-lib", ComponentType::Library).with_author("Test Publisher");

        let cyclone_comp = CycloneDxComponent::from_component(&comp);

        assert_eq!(cyclone_comp.publisher, Some("Test Publisher".to_string()));
    }

    #[test]
    fn test_service_without_author() {
        let comp = Component::new("anonymous-mcp", ComponentType::McpServer);
        let service = CycloneDxService::from_component(&comp);

        assert!(service.provider.is_none());
    }

    #[test]
    fn test_service_with_repository() {
        let comp = Component::new("repo-mcp", ComponentType::McpServer)
            .with_repository("https://github.com/test/mcp-server");

        let service = CycloneDxService::from_component(&comp);

        assert_eq!(service.external_references.len(), 1);
        assert_eq!(service.external_references[0].ref_type, "vcs");
    }

    #[test]
    fn test_bom_serial_number_format() {
        let bom = CycloneDxBom::from_components(&[]);

        assert!(bom.serial_number.starts_with("urn:uuid:"));
        // UUID format check
        let uuid_part = &bom.serial_number[9..];
        assert_eq!(uuid_part.len(), 36);
    }

    #[test]
    fn test_bom_metadata() {
        let bom = CycloneDxBom::from_components(&[]);

        assert_eq!(bom.metadata.tools.len(), 1);
        assert_eq!(bom.metadata.tools[0].vendor, "Anthropic");
        assert_eq!(bom.metadata.tools[0].name, "cc-audit");
    }

    #[test]
    fn test_bom_clone() {
        let components = vec![Component::new("test", ComponentType::Library).with_version("1.0.0")];
        let bom = CycloneDxBom::from_components(&components);
        let cloned = bom.clone();

        assert_eq!(cloned.bom_format, bom.bom_format);
        assert_eq!(cloned.spec_version, bom.spec_version);
        assert_eq!(cloned.components.len(), bom.components.len());
    }

    #[test]
    fn test_bom_deserialization() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:12345678-1234-1234-1234-123456789abc",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": []
            },
            "components": [],
            "services": []
        }"#;

        let bom: CycloneDxBom = serde_json::from_str(json).unwrap();
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.5");
    }

    #[test]
    fn test_license_info_with_name() {
        let license = CycloneDxLicenseInfo {
            id: None,
            name: Some("Custom License".to_string()),
        };

        let json = serde_json::to_string(&license).unwrap();
        assert!(json.contains("Custom License"));
        assert!(!json.contains("id"));
    }

    #[test]
    fn test_external_ref_serialization() {
        let ext_ref = CycloneDxExternalRef {
            ref_type: "website".to_string(),
            url: "https://example.com".to_string(),
        };

        let json = serde_json::to_string(&ext_ref).unwrap();
        assert!(json.contains("website"));
        assert!(json.contains("https://example.com"));
    }

    #[test]
    fn test_provider_serialization() {
        let provider = CycloneDxProvider {
            name: "Test Provider".to_string(),
        };

        let json = serde_json::to_string(&provider).unwrap();
        assert!(json.contains("Test Provider"));
    }

    #[test]
    fn test_empty_bom() {
        let bom = CycloneDxBom::from_components(&[]);

        assert!(bom.components.is_empty());
        assert!(bom.services.is_empty());
        assert_eq!(bom.version, 1);
    }

    #[test]
    fn test_multiple_component_types() {
        let components = vec![
            Component::new("app", ComponentType::Application),
            Component::new("lib", ComponentType::Library),
            Component::new("skill", ComponentType::Skill),
            Component::new("plugin", ComponentType::Plugin),
            Component::new("subagent", ComponentType::Subagent),
        ];

        let bom = CycloneDxBom::from_components(&components);

        // All should be in components (not services)
        assert_eq!(bom.components.len(), 5);
        assert_eq!(bom.services.len(), 0);
    }
}
