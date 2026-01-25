# Branch protection ruleset for main branch
resource "github_repository_ruleset" "protect_main" {
  name        = "protect-main-branch"
  repository  = var.repository_name
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["refs/heads/main"]
      exclude = []
    }
  }

  rules {
    # Prevent direct push (require PR)
    pull_request {
      required_review_thread_resolution = true
    }

    # Prevent force push and deletion
    deletion         = false
    non_fast_forward = false

    # Required status checks (only if checks are configured)
    dynamic "required_status_checks" {
      for_each = length(var.required_status_checks) > 0 ? [1] : []
      content {
        strict_required_status_checks_policy = true

        dynamic "required_check" {
          for_each = var.required_status_checks
          content {
            context = required_check.value
          }
        }
      }
    }
  }
}
