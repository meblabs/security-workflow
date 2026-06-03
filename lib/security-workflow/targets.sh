#!/usr/bin/env bash
# Target flags are intentionally written for the entrypoint, reports, and GitHub outputs.
# shellcheck disable=SC2034

security_workflow_detect_targets() {
  local root_dockerfile=false
  if [[ -f "$SECURITY_WORKFLOW_DOCKERFILE_PATH" ]]; then
    root_dockerfile=true
  fi

  local dockerfiles_count
  dockerfiles_count="$(find . \
    -type f \( -iname 'Dockerfile' -o -iname '*.Dockerfile' -o -name 'Dockerfile.*' \) \
    -not -path './node_modules/*' \
    -not -path './.git/*' \
    -not -path './.security-workflow/*' \
    -not -path './security-reports/*' \
    -print | wc -l | tr -d ' ')"

  local sam_templates_count
  sam_templates_count="$(find . \
    -type f \( -name 'template.yaml' -o -name 'template.yml' \) \
    -not -path './node_modules/*' \
    -not -path './.git/*' \
    -not -path './.security-workflow/*' \
    -not -path './security-reports/*' \
    -print | wc -l | tr -d ' ')"

  local github_actions_files_count
  github_actions_files_count="$(find . \
    -type f \( \
      -path './.github/workflows/*.yml' \
      -o -path './.github/workflows/*.yaml' \
      -o -name 'action.yml' \
      -o -name 'action.yaml' \
    \) \
    -not -path './node_modules/*' \
    -not -path './.git/*' \
    -not -path './.security-workflow/*' \
    -not -path './security-reports/*' \
    -print | wc -l | tr -d ' ')"

  ROOT_DOCKERFILE="$root_dockerfile"
  DOCKERFILES=false
  SAM_TEMPLATES=false
  GITHUB_ACTIONS_FILES=false
  DOCKERFILES_COUNT="$dockerfiles_count"
  SAM_TEMPLATES_COUNT="$sam_templates_count"
  GITHUB_ACTIONS_FILES_COUNT="$github_actions_files_count"

  if [[ "$dockerfiles_count" -gt 0 ]]; then
    DOCKERFILES=true
  fi

  if [[ "$sam_templates_count" -gt 0 ]]; then
    SAM_TEMPLATES=true
  fi

  if [[ "$github_actions_files_count" -gt 0 ]]; then
    GITHUB_ACTIONS_FILES=true
  fi

  {
    echo "## Detected optional targets"
    echo ""
    echo "- Configured Dockerfile for image scan: ${ROOT_DOCKERFILE}"
    echo "- Dockerfile/config files: ${DOCKERFILES_COUNT}"
    echo "- SAM/CloudFormation templates: ${SAM_TEMPLATES_COUNT}"
    echo "- GitHub Actions/action files: ${GITHUB_ACTIONS_FILES_COUNT}"
    echo ""
  } >> "$SECURITY_WORKFLOW_REPORTS_DIR/security-summary.md"
}
