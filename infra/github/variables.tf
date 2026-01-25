variable "github_owner" {
  description = "GitHub organization or username"
  type        = string
  default     = "ryo-ebata"
}

variable "repository_name" {
  description = "Name of the repository to protect"
  type        = string
  default     = "cc-audit"
}

variable "required_status_checks" {
  description = "List of required CI status checks"
  type        = list(string)
  default = [
    "CI Result",
    "Security Result",
    "Self Audit Result",
    "MSRV Result",
    "Performance Result",
    "Semver Result",
    "Terraform Result"
  ]
}
