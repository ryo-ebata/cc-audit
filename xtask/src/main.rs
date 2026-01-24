use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Development tasks for cc-audit")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new security rule
    NewRule {
        /// Category: exfiltration, privilege, persistence, injection, permission, obfuscation
        #[arg(short, long)]
        category: String,

        /// Rule ID (e.g., PE-006)
        #[arg(short, long)]
        id: String,

        /// Rule name (e.g., "Setuid bit manipulation")
        #[arg(short, long)]
        name: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::NewRule { category, id, name } => new_rule(&category, &id, &name),
    }
}

fn new_rule(category: &str, id: &str, name: &str) -> Result<()> {
    let (file_name, category_enum) = match category.to_lowercase().as_str() {
        "exfiltration" | "ex" => ("exfiltration", "Exfiltration"),
        "privilege" | "pe" => ("privilege", "PrivilegeEscalation"),
        "persistence" | "ps" => ("persistence", "Persistence"),
        "injection" | "pi" => ("injection", "PromptInjection"),
        "permission" | "op" => ("permission", "Overpermission"),
        "obfuscation" | "ob" => ("obfuscation", "Obfuscation"),
        _ => bail!(
            "Unknown category: {}. Valid: exfiltration, privilege, persistence, injection, permission, obfuscation",
            category
        ),
    };

    // Validate ID format
    let id_upper = id.to_uppercase();
    if !id_upper.contains('-') {
        bail!("ID must contain a hyphen (e.g., PE-006)");
    }

    let parts: Vec<&str> = id_upper.split('-').collect();
    if parts.len() != 2 {
        bail!("ID must be in format XX-NNN (e.g., PE-006)");
    }

    let fn_name = id_upper.to_lowercase().replace('-', "_");

    // Find project root
    let project_root = find_project_root()?;
    let file_path = project_root
        .join("src/rules/builtin")
        .join(format!("{}.rs", file_name));

    if !file_path.exists() {
        bail!("Category file not found: {:?}", file_path);
    }

    let content = fs::read_to_string(&file_path)?;

    // Check if rule already exists
    if content.contains(&format!("fn {}()", fn_name)) {
        bail!("Rule {} already exists in {}.rs", fn_name, file_name);
    }

    // Generate new rule function
    let rule_template = generate_rule_template(&fn_name, &id_upper, name, category_enum);
    let test_template = generate_test_template(&fn_name, &id_upper);

    // Find insertion points and modify content
    let new_content = insert_rule(&content, &fn_name, &rule_template, &test_template)?;

    fs::write(&file_path, new_content)?;

    println!(
        "Created rule {} in src/rules/builtin/{}.rs",
        id_upper, file_name
    );
    println!();
    println!("Next steps:");
    println!("  1. Edit the patterns in fn {}()", fn_name);
    println!("  2. Update the test cases in test_{}()", fn_name);
    println!("  3. Run: just test");

    Ok(())
}

fn find_project_root() -> Result<PathBuf> {
    let mut path = std::env::current_dir()?;
    loop {
        if path.join("Cargo.toml").exists() && path.join("src/rules").exists() {
            return Ok(path);
        }
        if !path.pop() {
            bail!("Could not find project root (no Cargo.toml with src/rules found)");
        }
    }
}

fn generate_rule_template(fn_name: &str, id: &str, name: &str, category: &str) -> String {
    format!(
        r#"fn {fn_name}() -> Rule {{
    Rule {{
        id: "{id}",
        name: "{name}",
        description: "TODO: Add description",
        severity: Severity::High,
        category: Category::{category},
        patterns: vec![
            Regex::new(r"TODO_PATTERN").unwrap(),
        ],
        exclusions: vec![],
        message: "TODO: Add user-facing message",
        recommendation: "TODO: Add recommendation",
    }}
}}
"#,
        fn_name = fn_name,
        id = id,
        name = name,
        category = category
    )
}

fn generate_test_template(fn_name: &str, id: &str) -> String {
    format!(
        r#"    #[test]
    fn test_{fn_name}() {{
        let rule = {fn_name}();
        let test_cases = vec![
            ("TODO: matching case", true),
            ("TODO: non-matching case", false),
        ];

        for (input, should_match) in test_cases {{
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "{id}: Failed for input: {{}}", input);
        }}
    }}"#,
        fn_name = fn_name,
        id = id
    )
}

fn insert_rule(
    content: &str,
    fn_name: &str,
    rule_template: &str,
    test_template: &str,
) -> Result<String> {
    let mut lines: Vec<String> = content.lines().map(String::from).collect();

    // 1. Find and update the rules() function
    let rules_fn_updated = update_rules_function(&mut lines, fn_name)?;
    if !rules_fn_updated {
        bail!("Could not find rules() function to update");
    }

    // 2. Find the last rule function and insert after it (before #[cfg(test)])
    let rule_insert_idx = find_rule_insert_position(&lines)?;
    let rule_lines: Vec<String> = rule_template.lines().map(String::from).collect();
    for (i, line) in rule_lines.into_iter().enumerate() {
        lines.insert(rule_insert_idx + i, line);
    }

    // 3. Find the tests module and insert test at the end
    let test_insert_idx = find_test_insert_position(&lines)?;

    // Insert empty line before test
    lines.insert(test_insert_idx, String::new());

    let test_lines: Vec<String> = test_template.lines().map(String::from).collect();
    for (i, line) in test_lines.into_iter().enumerate() {
        lines.insert(test_insert_idx + 1 + i, line);
    }

    Ok(lines.join("\n"))
}

fn update_rules_function(lines: &mut [String], fn_name: &str) -> Result<bool> {
    for (i, line) in lines.iter_mut().enumerate() {
        // Find: vec![pe_001(), pe_002(), ...]
        if line.contains("vec![") && line.contains("()]") {
            // Check if it's in the rules() function context (within first 10 lines)
            if i < 15 {
                // Add the new function call before the closing bracket
                let trimmed = line.trim_end();
                if trimmed.ends_with(']') {
                    *line = trimmed.strip_suffix(']').unwrap().to_string() + ", " + fn_name + "()]";
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn find_rule_insert_position(lines: &[String]) -> Result<usize> {
    // Find #[cfg(test)] and insert before it
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(test)]" {
            return Ok(i);
        }
    }
    // If no test module, insert at end
    Ok(lines.len())
}

fn find_test_insert_position(lines: &[String]) -> Result<usize> {
    // Find the closing brace of the tests module (mod tests { ... })
    let mut in_tests = false;
    let mut test_module_start = None;
    let mut brace_depth = 0;

    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(test)]" {
            in_tests = true;
            continue;
        }
        if in_tests && test_module_start.is_none() && line.contains("mod tests") {
            test_module_start = Some(i);
        }
        if test_module_start.is_some() {
            brace_depth += line.matches('{').count() as i32;
            brace_depth -= line.matches('}').count() as i32;

            // When we return to depth 0, we found the closing brace
            if brace_depth == 0 {
                // Return position just before the closing brace
                return Ok(i);
            }
        }
    }

    bail!("Could not find test module closing brace")
}
