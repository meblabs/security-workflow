#!/usr/bin/env bash

security_workflow_log() {
  printf '%s\n' "$*"
}

security_workflow_warn() {
  printf 'WARN: %s\n' "$*" >&2
}

security_workflow_error() {
  printf 'ERROR: %s\n' "$*" >&2
}

security_workflow_color_enabled() {
  case "${SECURITY_WORKFLOW_FORCE_COLOR:-${FORCE_COLOR:-}}" in
    1|true|yes|on) return 0 ;;
  esac

  if [[ -n "${NO_COLOR:-}" ]]; then
    return 1
  fi

  [[ -t 1 ]]
}

security_workflow_color() {
  local color="$1"
  local text="$2"

  if ! security_workflow_color_enabled; then
    printf '%s' "$text"
    return
  fi

  case "$color" in
    red) printf '\033[31m%s\033[0m' "$text" ;;
    green) printf '\033[32m%s\033[0m' "$text" ;;
    yellow) printf '\033[33m%s\033[0m' "$text" ;;
    *) printf '%s' "$text" ;;
  esac
}

security_workflow_pass_label() {
  security_workflow_color green PASS
}

security_workflow_fail_label() {
  security_workflow_color red FAIL
}

security_workflow_skip_label() {
  security_workflow_color yellow SKIP
}

security_workflow_command_exists() {
  command -v "$1" >/dev/null 2>&1
}

security_workflow_abs_path() {
  local path="$1"
  if [[ -d "$path" ]]; then
    (cd "$path" && pwd -P)
    return
  fi

  local dir
  local base
  dir="$(dirname "$path")"
  base="$(basename "$path")"
  (cd "$dir" && printf '%s/%s\n' "$(pwd -P)" "$base")
}

security_workflow_csv_to_flags() {
  local flag="$1"
  local csv="$2"
  local item
  local old_ifs="$IFS"

  IFS=','
  for item in $csv; do
    item="$(printf '%s' "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$item" ]] && continue
    printf '%s\0%s\0' "$flag" "$item"
  done
  IFS="$old_ifs"
}

security_workflow_check_in_list() {
  local wanted="$1"
  shift

  local item
  for item in "$@"; do
    if [[ "$item" == "$wanted" ]]; then
      return 0
    fi
  done

  return 1
}

security_workflow_only_checks_count() {
  local count=0
  local check
  for check in "${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]+"${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]}"}"; do
    count=$((count + 1))
  done
  printf '%s\n' "$count"
}

security_workflow_skip_checks_count() {
  local count=0
  local check
  for check in "${SECURITY_WORKFLOW_SKIP_CHECKS_EXPANDED[@]+"${SECURITY_WORKFLOW_SKIP_CHECKS_EXPANDED[@]}"}"; do
    count=$((count + 1))
  done
  printf '%s\n' "$count"
}

security_workflow_expand_check_selector() {
  local selector="$1"

  case "$selector" in
    all)
      printf '%s\n' semgrep gitleaks trivy-fs trivy-config cfn-lint zizmor docker-build trivy-image license sbom-fs sbom-image
      ;;
    trivy)
      printf '%s\n' trivy-fs trivy-config trivy-image license sbom-fs sbom-image
      ;;
    docker)
      printf '%s\n' docker-build trivy-image sbom-image
      ;;
    sbom)
      printf '%s\n' sbom-fs sbom-image
      ;;
    trivy-sbom)
      printf '%s\n' sbom-fs sbom-image
      ;;
    *)
      printf '%s\n' "$selector"
      ;;
  esac
}

security_workflow_parse_check_selectors() {
  local raw="$1"
  local output_var="$2"
  local expanded=()
  local old_ifs="$IFS"
  local selector
  local check

  IFS=','
  for selector in $raw; do
    selector="$(printf '%s' "$selector" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$selector" ]] && continue

    while IFS= read -r check; do
      [[ -z "$check" ]] && continue
      expanded+=("$check")
    done < <(security_workflow_expand_check_selector "$selector")
  done
  IFS="$old_ifs"

  eval "$output_var=()"
  for check in "${expanded[@]+"${expanded[@]}"}"; do
    eval "$output_var+=(\"\$check\")"
  done
}

security_workflow_validate_check_selectors() {
  local check

  for check in "${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]+"${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]}"}" "${SECURITY_WORKFLOW_SKIP_CHECKS_EXPANDED[@]+"${SECURITY_WORKFLOW_SKIP_CHECKS_EXPANDED[@]}"}"; do
    [[ -z "$check" ]] && continue
    case "$check" in
      semgrep|gitleaks|trivy-fs|trivy-config|cfn-lint|zizmor|docker-build|trivy-image|license|sbom-fs|sbom-image)
        ;;
      *)
        security_workflow_error "Unknown check selector: $check"
        security_workflow_error "Use one of: semgrep, gitleaks, trivy-fs, trivy-config, cfn-lint, zizmor, docker-build, trivy-image, license, sbom, sbom-fs, sbom-image, docker, trivy, all."
        return 2
        ;;
    esac
  done
}

security_workflow_add_implicit_check_dependencies() {
  if [[ "$(security_workflow_only_checks_count)" -eq 0 ]]; then
    return
  fi

  if security_workflow_check_in_list trivy-image "${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]+"${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]}"}" || security_workflow_check_in_list sbom-image "${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]+"${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]}"}"; then
    if ! security_workflow_check_in_list docker-build "${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]+"${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]}"}"; then
      SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED+=(docker-build)
    fi
  fi
}

security_workflow_check_enabled() {
  local check="$1"

  if [[ "$(security_workflow_only_checks_count)" -gt 0 ]] && ! security_workflow_check_in_list "$check" "${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]+"${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[@]}"}"; then
    return 1
  fi

  if [[ "$(security_workflow_skip_checks_count)" -gt 0 ]] && security_workflow_check_in_list "$check" "${SECURITY_WORKFLOW_SKIP_CHECKS_EXPANDED[@]+"${SECURITY_WORKFLOW_SKIP_CHECKS_EXPANDED[@]}"}"; then
    return 1
  fi

  return 0
}

security_workflow_log_selection() {
  local summary="$SECURITY_WORKFLOW_REPORTS_DIR/security-summary.md"

  if [[ -z "$SECURITY_WORKFLOW_ONLY_CHECKS" && -z "$SECURITY_WORKFLOW_SKIP_CHECKS" ]]; then
    return
  fi

  {
    echo "## Local check selection"
    echo ""
    if [[ -n "$SECURITY_WORKFLOW_ONLY_CHECKS" ]]; then
      echo "- Only: ${SECURITY_WORKFLOW_ONLY_CHECKS}"
    fi
    if [[ -n "$SECURITY_WORKFLOW_SKIP_CHECKS" ]]; then
      echo "- Skip: ${SECURITY_WORKFLOW_SKIP_CHECKS}"
    fi
    echo ""
  } >> "$summary"
}

security_workflow_prepare_reports() {
  if [[ -z "${SECURITY_WORKFLOW_REPORTS_DIR:-}" || "$SECURITY_WORKFLOW_REPORTS_DIR" == "/" ]]; then
    security_workflow_error "Invalid reports directory: ${SECURITY_WORKFLOW_REPORTS_DIR:-empty}"
    return 2
  fi

  rm -rf "$SECURITY_WORKFLOW_REPORTS_DIR"
  mkdir -p "$SECURITY_WORKFLOW_REPORTS_DIR"
  SECURITY_WORKFLOW_REPORTS_DIR="$(security_workflow_abs_path "$SECURITY_WORKFLOW_REPORTS_DIR")"

  SECURITY_WORKFLOW_COMMIT="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
  SECURITY_WORKFLOW_REPOSITORY_NAME="$(basename "$SECURITY_WORKFLOW_REPO")"

  {
    echo "# Security report"
    echo ""
    echo "- Repository: ${GITHUB_REPOSITORY:-$SECURITY_WORKFLOW_REPOSITORY_NAME}"
    echo "- Ref: ${SECURITY_WORKFLOW_REF}"
    echo "- Commit: ${SECURITY_WORKFLOW_COMMIT}"
    if [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "${GITHUB_RUN_ID:-}" ]]; then
      echo "- Run: ${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
    else
      echo "- Run: local"
    fi
    echo ""
  } > "$SECURITY_WORKFLOW_REPORTS_DIR/security-summary.md"
}

security_workflow_set_outcome() {
  local name="$1"
  local value="$2"
  eval "${name}=\"${value}\""
}

security_workflow_run_step() {
  local outcome_var="$1"
  local label="$2"
  shift 2

  security_workflow_log ""
  security_workflow_log "==> ${label}"

  set +e
  (set -euo pipefail; "$@")
  local status="$?"
  set -e

  if [[ "$status" -eq 0 ]]; then
    security_workflow_set_outcome "$outcome_var" "success"
    security_workflow_log "$(security_workflow_pass_label): ${label}"
  else
    security_workflow_set_outcome "$outcome_var" "failure"
    security_workflow_log "$(security_workflow_fail_label): ${label} exited with status ${status}."
  fi
}

security_workflow_status_badge() {
  case "$1" in
    success) echo "![PASS](https://img.shields.io/badge/status-PASS-brightgreen?style=flat-square)" ;;
    failure) echo "![FAIL](https://img.shields.io/badge/status-FAIL-red?style=flat-square)" ;;
    skipped) echo "![FAIL](https://img.shields.io/badge/status-FAIL-red?style=flat-square)" ;;
    cancelled) echo "![FAIL](https://img.shields.io/badge/status-FAIL-red?style=flat-square)" ;;
    na) echo "![NA](https://img.shields.io/badge/status-NA-lightgrey?style=flat-square)" ;;
    *) echo "![UNKNOWN](https://img.shields.io/badge/status-UNKNOWN-lightgrey?style=flat-square)" ;;
  esac
}

security_workflow_applicable_badge() {
  local outcome="$1"
  local applicable="$2"

  if [[ "$applicable" != "true" ]]; then
    security_workflow_status_badge na
    return
  fi

  security_workflow_status_badge "$outcome"
}
