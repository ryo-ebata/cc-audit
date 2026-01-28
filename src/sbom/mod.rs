//! SBOM (Software Bill of Materials) generation module.
//!
//! This module provides functionality to generate SBOMs for Claude Code
//! configurations, including MCP servers, skills, and dependencies.

pub mod builder;
pub mod cyclonedx;
pub mod extractor;
pub mod spdx;

pub use builder::{Component, ComponentType, SbomBuilder, SbomFormat};
pub use cyclonedx::CycloneDxBom;
pub use extractor::DependencyExtractor;
pub use spdx::SpdxDocument;
