# Tag protection ruleset for release tags (v*)
resource "github_repository_ruleset" "protect_release_tags" {
  name        = "protect-release-tags"
  repository  = var.repository_name
  target      = "tag"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["refs/tags/v*"]
      exclude = []
    }
  }

  rules {
    # Allow tag creation (omit or set false)
    # creation = false

    # Prevent tag update (history tampering)
    update = true

    # Prevent tag deletion (release removal)
    deletion = true
  }
}
