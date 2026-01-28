//! SPDX 2.3 format support for SBOM generation.

use serde::{Deserialize, Serialize};

use super::builder::{Component, ComponentType};

/// SPDX 2.3 document structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxDocument {
    /// SPDX version (always "SPDX-2.3")
    pub spdx_version: String,

    /// Data license (CC0-1.0 for SPDX)
    pub data_license: String,

    /// SPDX identifier for the document
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,

    /// Document name
    pub name: String,

    /// Document namespace (unique URL)
    pub document_namespace: String,

    /// Creation information
    pub creation_info: CreationInfo,

    /// Packages in the document
    pub packages: Vec<SpdxPackage>,

    /// Relationships between packages
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<Relationship>,
}

/// SPDX creation information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationInfo {
    /// Creation timestamp (ISO 8601)
    pub created: String,

    /// Tool(s) used to create the SPDX document
    pub creators: Vec<String>,
}

/// SPDX package representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxPackage {
    /// SPDX identifier for the package
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,

    /// Package name
    pub name: String,

    /// Package version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<String>,

    /// Download location (NOASSERTION if unknown)
    pub download_location: String,

    /// Files analyzed flag
    pub files_analyzed: bool,

    /// License concluded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_concluded: Option<String>,

    /// License declared
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_declared: Option<String>,

    /// Copyright text
    pub copyright_text: String,

    /// Package supplier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplier: Option<String>,

    /// Package description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// External references (e.g., purl)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_refs: Vec<ExternalRef>,

    /// Checksums
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checksums: Vec<Checksum>,

    /// Primary package purpose
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_package_purpose: Option<String>,
}

/// SPDX external reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalRef {
    /// Reference category
    pub reference_category: String,

    /// Reference type
    pub reference_type: String,

    /// Reference locator (e.g., purl)
    pub reference_locator: String,
}

/// SPDX checksum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checksum {
    /// Algorithm used
    pub algorithm: String,

    /// Checksum value
    pub checksum_value: String,
}

/// SPDX relationship between packages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Relationship {
    /// SPDX ID of the element
    pub spdx_element_id: String,

    /// Relationship type
    pub relationship_type: String,

    /// Related SPDX element ID
    pub related_spdx_element: String,
}

impl SpdxDocument {
    /// Create a new SPDX document from components.
    pub fn from_components(components: &[Component]) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let uuid = uuid::Uuid::new_v4();

        let packages: Vec<SpdxPackage> = components
            .iter()
            .enumerate()
            .map(|(i, c)| SpdxPackage::from_component(c, i))
            .collect();

        // Create relationships (all packages DESCRIBED_BY the document)
        let mut relationships: Vec<Relationship> = packages
            .iter()
            .map(|p| Relationship {
                spdx_element_id: "SPDXRef-DOCUMENT".to_string(),
                relationship_type: "DESCRIBES".to_string(),
                related_spdx_element: p.spdx_id.clone(),
            })
            .collect();

        // Add root package relationship if there are packages
        if !packages.is_empty() {
            relationships.push(Relationship {
                spdx_element_id: packages[0].spdx_id.clone(),
                relationship_type: "DEPENDENCY_OF".to_string(),
                related_spdx_element: "SPDXRef-DOCUMENT".to_string(),
            });
        }

        Self {
            spdx_version: "SPDX-2.3".to_string(),
            data_license: "CC0-1.0".to_string(),
            spdx_id: "SPDXRef-DOCUMENT".to_string(),
            name: "cc-audit SBOM".to_string(),
            document_namespace: format!("https://github.com/ryo-ebata/cc-audit/spdx/{}", uuid),
            creation_info: CreationInfo {
                created: timestamp,
                creators: vec![format!("Tool: cc-audit-{}", env!("CARGO_PKG_VERSION"))],
            },
            packages,
            relationships,
        }
    }
}

impl SpdxPackage {
    /// Create an SPDX package from a component.
    fn from_component(component: &Component, index: usize) -> Self {
        let spdx_id = format!("SPDXRef-Package-{}", index + 1);

        let mut external_refs = Vec::new();
        if let Some(ref purl) = component.purl {
            external_refs.push(ExternalRef {
                reference_category: "PACKAGE-MANAGER".to_string(),
                reference_type: "purl".to_string(),
                reference_locator: purl.clone(),
            });
        }

        let mut checksums = Vec::new();
        if let Some(ref hash) = component.hash_sha256 {
            checksums.push(Checksum {
                algorithm: "SHA256".to_string(),
                checksum_value: hash.clone(),
            });
        }

        let download_location = component
            .repository
            .clone()
            .unwrap_or_else(|| "NOASSERTION".to_string());

        let supplier = component.author.as_ref().map(|a| format!("Person: {}", a));

        Self {
            spdx_id,
            name: component.name.clone(),
            version_info: component.version.clone(),
            download_location,
            files_analyzed: false,
            license_concluded: component.license.clone(),
            license_declared: component.license.clone(),
            copyright_text: "NOASSERTION".to_string(),
            supplier,
            description: component.description.clone(),
            external_refs,
            checksums,
            primary_package_purpose: Some(component_type_to_spdx_purpose(
                &component.component_type,
            )),
        }
    }
}

/// Convert component type to SPDX primary package purpose.
fn component_type_to_spdx_purpose(component_type: &ComponentType) -> String {
    match component_type {
        ComponentType::Application => "APPLICATION".to_string(),
        ComponentType::Library => "LIBRARY".to_string(),
        ComponentType::Service => "SOURCE".to_string(), // SPDX doesn't have SERVICE
        ComponentType::McpServer => "APPLICATION".to_string(),
        ComponentType::Skill => "APPLICATION".to_string(),
        ComponentType::Plugin => "LIBRARY".to_string(),
        ComponentType::Subagent => "APPLICATION".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spdx_document_from_components() {
        let components = vec![
            Component::new("test-package", ComponentType::Library)
                .with_version("1.0.0")
                .with_purl("pkg:npm/test-package@1.0.0"),
        ];

        let doc = SpdxDocument::from_components(&components);

        assert_eq!(doc.spdx_version, "SPDX-2.3");
        assert_eq!(doc.data_license, "CC0-1.0");
        assert_eq!(doc.packages.len(), 1);
        assert_eq!(doc.packages[0].name, "test-package");
        assert_eq!(doc.packages[0].version_info, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_spdx_package_external_refs() {
        let component =
            Component::new("test", ComponentType::Library).with_purl("pkg:npm/test@1.0.0");

        let package = SpdxPackage::from_component(&component, 0);

        assert_eq!(package.external_refs.len(), 1);
        assert_eq!(package.external_refs[0].reference_type, "purl");
        assert_eq!(
            package.external_refs[0].reference_locator,
            "pkg:npm/test@1.0.0"
        );
    }

    #[test]
    fn test_spdx_package_checksums() {
        let component = Component::new("test", ComponentType::Library).with_hash("abc123def456");

        let package = SpdxPackage::from_component(&component, 0);

        assert_eq!(package.checksums.len(), 1);
        assert_eq!(package.checksums[0].algorithm, "SHA256");
        assert_eq!(package.checksums[0].checksum_value, "abc123def456");
    }

    #[test]
    fn test_component_type_to_spdx_purpose() {
        assert_eq!(
            component_type_to_spdx_purpose(&ComponentType::Application),
            "APPLICATION"
        );
        assert_eq!(
            component_type_to_spdx_purpose(&ComponentType::Library),
            "LIBRARY"
        );
        assert_eq!(
            component_type_to_spdx_purpose(&ComponentType::McpServer),
            "APPLICATION"
        );
    }

    #[test]
    fn test_spdx_serialization() {
        let components = vec![Component::new("test", ComponentType::Library)];
        let doc = SpdxDocument::from_components(&components);

        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(json.contains("SPDX-2.3"));
        assert!(json.contains("test"));
    }
}
