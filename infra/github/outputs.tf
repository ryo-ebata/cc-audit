output "repository_name" {
  description = "Name of the protected repository"
  value       = data.github_repository.cc_audit.name
}

output "branch_ruleset_name" {
  description = "Branch protection ruleset name"
  value       = github_repository_ruleset.protect_main.name
}

output "tag_ruleset_name" {
  description = "Tag protection ruleset name"
  value       = github_repository_ruleset.protect_release_tags.name
}

output "required_status_checks" {
  description = "Required status checks for merge"
  value       = var.required_status_checks
}
