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
    security_workflow_log "PASS: ${label}"
  else
    security_workflow_set_outcome "$outcome_var" "failure"
    security_workflow_log "FAIL: ${label} exited with status ${status}."
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
