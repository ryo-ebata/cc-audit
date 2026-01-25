# Reference existing repository (do not manage with Terraform)
data "github_repository" "cc_audit" {
  full_name = "${var.github_owner}/${var.repository_name}"
}
