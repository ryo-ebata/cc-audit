# Parser Module (L4)

The content parsing layer provides parsers for different file formats.

## Architecture Layer

**Layer 4 (Parser)** - Receives file paths from L3 (Discovery) and provides parsed content to L5 (Detection Engine).

## Responsibilities

- Parse different file formats into structured data
- Extract frontmatter from Markdown files
- Provide a unified interface for content parsing

## Files

| File | Parser | Description |
|------|--------|-------------|
| `mod.rs` | `ParserRegistry` | Module exports, registry |
| `traits.rs` | `ContentParser`, `ContentType`, `ParsedContent` | Trait definitions |
| `markdown.rs` | `MarkdownParser` | SKILL.md, CLAUDE.md, commands |
| `json.rs` | `JsonParser` | mcp.json, package.json |
| `yaml.rs` | `YamlParser` | docker-compose.yml, configs |
| `toml.rs` | `TomlParser` | Cargo.toml, pyproject.toml |
| `dockerfile.rs` | `DockerfileParser` | Dockerfile parsing |
| `frontmatter.rs` | `FrontmatterParser` | YAML frontmatter extraction |

## Key Types

### ContentParser Trait

```rust
pub trait ContentParser: Send + Sync {
    fn can_parse(&self, path: &str) -> bool;
    fn parse(&self, content: &str, path: &str) -> Result<ParsedContent>;
}
```

### ParsedContent

```rust
pub struct ParsedContent {
    pub content_type: ContentType,
    pub raw_content: String,
    pub path: String,
    pub frontmatter: Option<Value>,
    pub structured_data: Option<Value>,
    pub sections: Vec<Section>,
}
```

### ContentType

```rust
pub enum ContentType {
    Markdown,
    Json,
    Yaml,
    Toml,
    Dockerfile,
    PlainText,
}
```

## ParserRegistry

Manages all available parsers:

```rust
pub struct ParserRegistry {
    parsers: Vec<Box<dyn ContentParser>>,
}

impl ParserRegistry {
    pub fn new() -> Self;
    pub fn find_parser(&self, path: &str) -> Option<&dyn ContentParser>;
    pub fn parse(&self, content: &str, path: &str) -> Result<ParsedContent>;
}
```

## Supported File Types

| Parser | Extensions/Names |
|--------|------------------|
| Markdown | `.md` |
| JSON | `.json` |
| YAML | `.yaml`, `.yml` |
| TOML | `.toml` |
| Dockerfile | `Dockerfile`, `Dockerfile.*` |

## Data Flow

```
┌─────────────────┐
│  Discovery (L3) │
│   File paths    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Parser      │
│  (This Module)  │
│   - Registry    │
│   - Parsers     │
└────────┬────────┘
         │ ParsedContent
         ▼
┌─────────────────┐
│   Engine (L5)   │
└─────────────────┘
```

## Usage Example

```rust
use cc_audit::parser::{ParserRegistry, ContentType, ParsedContent};

let registry = ParserRegistry::new();

// Parse based on file extension
let content = fs::read_to_string("SKILL.md")?;
let parsed = registry.parse(&content, "SKILL.md")?;

match parsed.content_type {
    ContentType::Markdown => {
        if let Some(frontmatter) = &parsed.frontmatter {
            println!("Name: {}", frontmatter["name"]);
        }
    }
    ContentType::Json => {
        if let Some(data) = &parsed.structured_data {
            println!("JSON data: {}", data);
        }
    }
    _ => {}
}
```

## Frontmatter Extraction

For Markdown files, frontmatter is automatically extracted:

```markdown
---
name: my-skill
description: A skill description
allowed_tools:
  - bash
---

# Skill Content
```

Becomes:

```rust
ParsedContent {
    frontmatter: Some(json!({
        "name": "my-skill",
        "description": "A skill description",
        "allowed_tools": ["bash"]
    })),
    // ...
}
```
