#!/usr/bin/env bash

security_workflow_normalize_sarif() {
  local file="$1"
  local name="$2"
  local organization="$3"
  local version="$4"

  if [[ ! -f "$file" ]]; then
    return
  fi

  if ! security_workflow_command_exists jq; then
    security_workflow_warn "jq is not available; skipping SARIF metadata normalization for $file."
    return
  fi

  jq \
    --arg name "$name" \
    --arg organization "$organization" \
    --arg version "$version" \
    '(.runs[]?.tool.driver.name) |= (. // $name) |
     (.runs[]?.tool.driver.organization) |= (. // $organization) |
     (.runs[]?.tool.driver.semanticVersion) |= (. // $version) |
     (.runs[]?.tool.driver.version) |= (. // $version)' \
    "$file" > "${file}.tmp"
  mv "${file}.tmp" "$file"
}

security_workflow_normalize_all_sarif() {
  security_workflow_normalize_sarif "$SECURITY_WORKFLOW_REPORTS_DIR/semgrep.sarif" Semgrep Semgrep "$SECURITY_WORKFLOW_SEMGREP_VERSION"
  security_workflow_normalize_sarif "$SECURITY_WORKFLOW_REPORTS_DIR/gitleaks.sarif" Gitleaks Gitleaks "$SECURITY_WORKFLOW_GITLEAKS_VERSION"
  security_workflow_normalize_sarif "$SECURITY_WORKFLOW_REPORTS_DIR/trivy-fs.sarif" Trivy AquaSecurity "$SECURITY_WORKFLOW_TRIVY_VERSION"
  security_workflow_normalize_sarif "$SECURITY_WORKFLOW_REPORTS_DIR/trivy-config.sarif" Trivy AquaSecurity "$SECURITY_WORKFLOW_TRIVY_VERSION"
  security_workflow_normalize_sarif "$SECURITY_WORKFLOW_REPORTS_DIR/trivy-image.sarif" Trivy AquaSecurity "$SECURITY_WORKFLOW_TRIVY_VERSION"
}

security_workflow_append_details() {
  local title="$1"
  local file="$2"
  local summary_file="$SECURITY_WORKFLOW_REPORTS_DIR/security-summary.md"

  if [[ -s "$file" ]]; then
    {
      echo "<details><summary>${title}</summary>"
      echo ""
      echo '```text'
      sed -n '1,200p' "$file"
      echo '```'
      echo "</details>"
      echo ""
    } >> "$summary_file"
  fi
}

security_workflow_write_summary() {
  local summary_file="$SECURITY_WORKFLOW_REPORTS_DIR/security-summary.md"

  {
    echo "## Security checks"
    echo ""
    echo "| Check | Outcome |"
    echo "|---|---:|"
    echo "| Semgrep SAST | $(security_workflow_status_badge "$SEMGREP_OUTCOME") |"
    echo "| Gitleaks secrets | $(security_workflow_status_badge "$GITLEAKS_OUTCOME") |"
    echo "| Trivy filesystem SCA | $(security_workflow_status_badge "$TRIVY_FS_OUTCOME") |"
    echo "| Trivy IaC/config misconfiguration | $(security_workflow_status_badge "$TRIVY_CONFIG_OUTCOME") |"
    echo "| cfn-lint SAM/CloudFormation validation | $(security_workflow_applicable_badge "$CFN_LINT_OUTCOME" "$SAM_TEMPLATES") |"
    echo "| zizmor GitHub Actions security | $(security_workflow_applicable_badge "$ZIZMOR_OUTCOME" "$GITHUB_ACTIONS_FILES") |"
    echo "| Docker image build | $(security_workflow_applicable_badge "$DOCKER_BUILD_OUTCOME" "$ROOT_DOCKERFILE") |"
    echo "| Trivy Docker image scan | $(security_workflow_applicable_badge "$TRIVY_IMAGE_OUTCOME" "$ROOT_DOCKERFILE") |"
    echo "| Trivy license report | $(security_workflow_status_badge "$TRIVY_LICENSE_OUTCOME") |"
    echo "| Trivy filesystem SBOM | $(security_workflow_status_badge "$TRIVY_SBOM_OUTCOME") |"
    echo "| Trivy Docker image SBOM | $(security_workflow_applicable_badge "$TRIVY_IMAGE_SBOM_OUTCOME" "$ROOT_DOCKERFILE") |"
    echo ""
    echo "Detailed failure output is included below. The security-reports artifact contains the same reports for download or audit retention."
    echo ""
  } >> "$summary_file"

  security_workflow_append_details "cfn-lint output" "$SECURITY_WORKFLOW_REPORTS_DIR/cfn-lint.txt"
  security_workflow_append_details "zizmor output" "$SECURITY_WORKFLOW_REPORTS_DIR/zizmor.txt"

  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    cat "$summary_file" >> "$GITHUB_STEP_SUMMARY"
  fi
}

security_workflow_json_bool() {
  case "$1" in
    true) printf 'true' ;;
    *) printf 'false' ;;
  esac
}

security_workflow_json_string() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

security_workflow_write_status_files() {
  local env_file="$SECURITY_WORKFLOW_REPORTS_DIR/security-status.env"
  local json_file="$SECURITY_WORKFLOW_REPORTS_DIR/security-status.json"

  {
    echo "ROOT_DOCKERFILE=${ROOT_DOCKERFILE}"
    echo "DOCKERFILES=${DOCKERFILES}"
    echo "SAM_TEMPLATES=${SAM_TEMPLATES}"
    echo "GITHUB_ACTIONS_FILES=${GITHUB_ACTIONS_FILES}"
    echo "DOCKERFILES_COUNT=${DOCKERFILES_COUNT}"
    echo "SAM_TEMPLATES_COUNT=${SAM_TEMPLATES_COUNT}"
    echo "GITHUB_ACTIONS_FILES_COUNT=${GITHUB_ACTIONS_FILES_COUNT}"
    echo "SEMGREP_OUTCOME=${SEMGREP_OUTCOME}"
    echo "GITLEAKS_OUTCOME=${GITLEAKS_OUTCOME}"
    echo "TRIVY_FS_OUTCOME=${TRIVY_FS_OUTCOME}"
    echo "TRIVY_CONFIG_OUTCOME=${TRIVY_CONFIG_OUTCOME}"
    echo "CFN_LINT_OUTCOME=${CFN_LINT_OUTCOME}"
    echo "ZIZMOR_OUTCOME=${ZIZMOR_OUTCOME}"
    echo "DOCKER_BUILD_OUTCOME=${DOCKER_BUILD_OUTCOME}"
    echo "TRIVY_IMAGE_OUTCOME=${TRIVY_IMAGE_OUTCOME}"
    echo "TRIVY_LICENSE_OUTCOME=${TRIVY_LICENSE_OUTCOME}"
    echo "TRIVY_SBOM_OUTCOME=${TRIVY_SBOM_OUTCOME}"
    echo "TRIVY_IMAGE_SBOM_OUTCOME=${TRIVY_IMAGE_SBOM_OUTCOME}"
    echo "SECURITY_GATE_OUTCOME=${SECURITY_GATE_OUTCOME}"
  } > "$env_file"

  cat > "$json_file" <<EOF
{
  "scannedRef": "$(security_workflow_json_string "$SECURITY_WORKFLOW_REF")",
  "commit": "$(security_workflow_json_string "$SECURITY_WORKFLOW_COMMIT")",
  "reportsDir": "$(security_workflow_json_string "$SECURITY_WORKFLOW_REPORTS_DIR")",
  "targets": {
    "rootDockerfile": $(security_workflow_json_bool "$ROOT_DOCKERFILE"),
    "dockerfiles": $(security_workflow_json_bool "$DOCKERFILES"),
    "samTemplates": $(security_workflow_json_bool "$SAM_TEMPLATES"),
    "githubActionsFiles": $(security_workflow_json_bool "$GITHUB_ACTIONS_FILES"),
    "dockerfilesCount": ${DOCKERFILES_COUNT},
    "samTemplatesCount": ${SAM_TEMPLATES_COUNT},
    "githubActionsFilesCount": ${GITHUB_ACTIONS_FILES_COUNT}
  },
  "checks": [
    { "id": "semgrep", "name": "Semgrep SAST", "outcome": "$SEMGREP_OUTCOME", "blocking": true, "applicable": true },
    { "id": "gitleaks", "name": "Gitleaks secrets", "outcome": "$GITLEAKS_OUTCOME", "blocking": true, "applicable": true },
    { "id": "trivy_fs", "name": "Trivy filesystem SCA", "outcome": "$TRIVY_FS_OUTCOME", "blocking": true, "applicable": true },
    { "id": "trivy_config", "name": "Trivy IaC/config misconfiguration", "outcome": "$TRIVY_CONFIG_OUTCOME", "blocking": true, "applicable": true },
    { "id": "cfn_lint", "name": "cfn-lint SAM/CloudFormation validation", "outcome": "$CFN_LINT_OUTCOME", "blocking": true, "applicable": $(security_workflow_json_bool "$SAM_TEMPLATES") },
    { "id": "zizmor", "name": "zizmor GitHub Actions security", "outcome": "$ZIZMOR_OUTCOME", "blocking": true, "applicable": $(security_workflow_json_bool "$GITHUB_ACTIONS_FILES") },
    { "id": "docker_build", "name": "Docker image build", "outcome": "$DOCKER_BUILD_OUTCOME", "blocking": true, "applicable": $(security_workflow_json_bool "$ROOT_DOCKERFILE") },
    { "id": "trivy_image", "name": "Trivy Docker image scan", "outcome": "$TRIVY_IMAGE_OUTCOME", "blocking": true, "applicable": $(security_workflow_json_bool "$ROOT_DOCKERFILE") },
    { "id": "trivy_license", "name": "Trivy license report", "outcome": "$TRIVY_LICENSE_OUTCOME", "blocking": false, "applicable": true },
    { "id": "trivy_sbom", "name": "Trivy filesystem SBOM", "outcome": "$TRIVY_SBOM_OUTCOME", "blocking": false, "applicable": true },
    { "id": "trivy_image_sbom", "name": "Trivy Docker image SBOM", "outcome": "$TRIVY_IMAGE_SBOM_OUTCOME", "blocking": false, "applicable": $(security_workflow_json_bool "$ROOT_DOCKERFILE") }
  ],
  "gate": {
    "outcome": "$SECURITY_GATE_OUTCOME"
  }
}
EOF
}

security_workflow_write_github_outputs() {
  if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
    return
  fi

  {
    echo "root_dockerfile=${ROOT_DOCKERFILE}"
    echo "dockerfiles=${DOCKERFILES}"
    echo "sam_templates=${SAM_TEMPLATES}"
    echo "github_actions_files=${GITHUB_ACTIONS_FILES}"
    echo "dockerfiles_count=${DOCKERFILES_COUNT}"
    echo "sam_templates_count=${SAM_TEMPLATES_COUNT}"
    echo "github_actions_files_count=${GITHUB_ACTIONS_FILES_COUNT}"
    echo "semgrep_outcome=${SEMGREP_OUTCOME}"
    echo "gitleaks_outcome=${GITLEAKS_OUTCOME}"
    echo "trivy_fs_outcome=${TRIVY_FS_OUTCOME}"
    echo "trivy_config_outcome=${TRIVY_CONFIG_OUTCOME}"
    echo "cfn_lint_outcome=${CFN_LINT_OUTCOME}"
    echo "zizmor_outcome=${ZIZMOR_OUTCOME}"
    echo "docker_build_outcome=${DOCKER_BUILD_OUTCOME}"
    echo "trivy_image_outcome=${TRIVY_IMAGE_OUTCOME}"
    echo "trivy_license_outcome=${TRIVY_LICENSE_OUTCOME}"
    echo "trivy_sbom_outcome=${TRIVY_SBOM_OUTCOME}"
    echo "trivy_image_sbom_outcome=${TRIVY_IMAGE_SBOM_OUTCOME}"
    echo "security_gate_outcome=${SECURITY_GATE_OUTCOME}"
  } >> "$GITHUB_OUTPUT"
}
