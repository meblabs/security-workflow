#!/usr/bin/env bash

security_workflow_require_docker() {
  if ! security_workflow_command_exists docker; then
    security_workflow_error "Docker is required to run the security scanners."
    return 127
  fi
}

security_workflow_semgrep() {
  security_workflow_require_docker || return $?

  local tmpdir
  tmpdir="$(mktemp -d)"
  security_workflow_copy_tracked_files "$tmpdir"

  local config_args=()
  local config
  for config in $SECURITY_WORKFLOW_SECURITY_CONFIG; do
    [[ -z "$config" ]] && continue
    config_args+=(--config "$config")
  done

  local severity_args=()
  local threshold
  threshold="$(printf '%s' "$SECURITY_WORKFLOW_SECURITY_SEVERITY_THRESHOLD" | tr '[:upper:]' '[:lower:]')"
  case "$threshold" in
    low|info)
      severity_args+=(--severity INFO --severity WARNING --severity ERROR)
      ;;
    medium|warning)
      severity_args+=(--severity WARNING --severity ERROR)
      ;;
    high|error|critical)
      severity_args+=(--severity ERROR)
      ;;
    *)
      security_workflow_error "Invalid security-severity-threshold: ${SECURITY_WORKFLOW_SECURITY_SEVERITY_THRESHOLD}"
      security_workflow_error "Use one of: low, medium, high, info, warning, error, critical."
      return 2
      ;;
  esac

  set +e
  docker run --rm \
    -v "$tmpdir:/src:ro" \
    -v "$SECURITY_WORKFLOW_REPORTS_DIR:/reports" \
    -w /src \
    "semgrep/semgrep:${SECURITY_WORKFLOW_SEMGREP_VERSION}" \
    semgrep scan \
    "${config_args[@]}" \
    "${severity_args[@]}" \
    --exclude node_modules \
    --exclude .git \
    --exclude .security-workflow \
    --exclude security-reports \
    --sarif \
    --output /reports/semgrep.sarif \
    --error \
    .
  local status="$?"
  set -e

  rm -rf "$tmpdir"
  return "$status"
}

security_workflow_copy_tracked_files() {
  local destination="$1"
  local file
  mkdir -p "$destination"

  while IFS= read -r -d '' file; do
    [[ -f "$file" ]] || continue
    mkdir -p "$destination/$(dirname "$file")"
    cp -p "$file" "$destination/$file"
  done < <(git ls-files -z)
}

security_workflow_gitleaks() {
  security_workflow_require_docker || return $?

  local tmpdir
  tmpdir="$(mktemp -d)"

  security_workflow_copy_tracked_files "$tmpdir"

  set +e
  docker run --rm \
    -v "$tmpdir:/scan:ro" \
    -v "$SECURITY_WORKFLOW_REPORTS_DIR:/reports" \
    "ghcr.io/gitleaks/gitleaks:${SECURITY_WORKFLOW_GITLEAKS_VERSION}" \
    dir /scan \
    --redact \
    --no-banner \
    --report-format sarif \
    --report-path /reports/gitleaks.sarif \
    --exit-code 1 \
    --log-level warn \
    --max-target-megabytes 2
  local status="$?"
  set -e

  rm -rf "$tmpdir"
  return "$status"
}

security_workflow_trivy_skip_args() {
  security_workflow_csv_to_flags "--skip-dirs" "$SECURITY_WORKFLOW_SECURITY_SKIP_DIRS"
}

security_workflow_trivy_docker_image() {
  local tag="$SECURITY_WORKFLOW_TRIVY_VERSION"
  tag="${tag#v}"
  printf 'aquasec/trivy:%s\n' "$tag"
}

security_workflow_zizmor_docker_image() {
  local tag="$SECURITY_WORKFLOW_ZIZMOR_VERSION"
  tag="${tag#v}"
  printf 'ghcr.io/zizmorcore/zizmor:%s\n' "$tag"
}

security_workflow_write_default_zizmor_config() {
  local config_path="$1"

  cat > "$config_path" <<'EOF'
rules:
  unpinned-uses:
    config:
      policies:
        meblabs/*: ref-pin
        actions/*: ref-pin
        aws-actions/*: ref-pin
EOF
}

security_workflow_trivy_fs() {
  security_workflow_require_docker || return $?

  local skip_args=()
  local skip_arg
  while IFS= read -r -d '' skip_arg; do
    skip_args+=("$skip_arg")
  done < <(security_workflow_trivy_skip_args)

  docker run --rm \
    -e TRIVY_LIMIT_SEVERITIES_FOR_SARIF=true \
    -v "$SECURITY_WORKFLOW_REPO:/repo:ro" \
    -v "$SECURITY_WORKFLOW_REPORTS_DIR:/reports" \
    "$(security_workflow_trivy_docker_image)" \
    fs /repo \
    --skip-version-check \
    --scanners vuln \
    --pkg-types os,library \
    --severity "$SECURITY_WORKFLOW_SECURITY_VULNERABILITY_SEVERITIES" \
    --ignore-unfixed \
    --exit-code 1 \
    --format sarif \
    --output /reports/trivy-fs.sarif \
    "${skip_args[@]}"
}

security_workflow_trivy_config() {
  security_workflow_require_docker || return $?

  local skip_args=()
  local skip_arg
  while IFS= read -r -d '' skip_arg; do
    skip_args+=("$skip_arg")
  done < <(security_workflow_trivy_skip_args)

  docker run --rm \
    -e TRIVY_LIMIT_SEVERITIES_FOR_SARIF=true \
    -v "$SECURITY_WORKFLOW_REPO:/repo:ro" \
    -v "$SECURITY_WORKFLOW_REPORTS_DIR:/reports" \
    "$(security_workflow_trivy_docker_image)" \
    config /repo \
    --skip-version-check \
    --severity "$SECURITY_WORKFLOW_SECURITY_VULNERABILITY_SEVERITIES" \
    --exit-code 1 \
    --format sarif \
    --output /reports/trivy-config.sarif \
    "${skip_args[@]}"
}

security_workflow_cfn_lint() {
  local venv_dir
  venv_dir="${RUNNER_TEMP:-/tmp}/cfn-lint-venv"

  if ! security_workflow_command_exists python3; then
    security_workflow_error "python3 is required to install and run cfn-lint."
    return 127
  fi

  python3 -m venv "$venv_dir"
  "$venv_dir/bin/python" -m pip install --quiet --upgrade pip
  "$venv_dir/bin/python" -m pip install --quiet 'cfn-lint[sarif]'

  local templates=()
  local template
  while IFS= read -r -d '' template; do
    templates+=("$template")
  done < <(find . \
    -type f \( -name 'template.yaml' -o -name 'template.yml' \) \
    -not -path './node_modules/*' \
    -not -path './.git/*' \
    -not -path './.security-workflow/*' \
    -not -path './security-reports/*' \
    -print0)

  if [[ "${#templates[@]}" -eq 0 ]]; then
    echo "No AWS SAM/CloudFormation templates found."
    return 0
  fi

  set +e
  "$venv_dir/bin/cfn-lint" --non-zero-exit-code error "${templates[@]}" 2>&1 | tee "$SECURITY_WORKFLOW_REPORTS_DIR/cfn-lint.txt"
  local status="${PIPESTATUS[0]}"
  set -e
  return "$status"
}

security_workflow_zizmor() {
  security_workflow_require_docker || return $?

  local docker_env=()
  if [[ -n "${SECURITY_WORKFLOW_GITHUB_TOKEN:-${GH_TOKEN:-}}" ]]; then
    docker_env=(-e "GH_TOKEN=${SECURITY_WORKFLOW_GITHUB_TOKEN:-${GH_TOKEN:-}}")
  else
    docker_env=(-e "ZIZMOR_OFFLINE=true")
  fi

  local config_path
  if [[ -n "$SECURITY_WORKFLOW_ZIZMOR_CONFIG" ]]; then
    config_path="$(security_workflow_abs_path "$SECURITY_WORKFLOW_ZIZMOR_CONFIG")"
    if [[ ! -f "$config_path" ]]; then
      security_workflow_error "zizmor config file not found: $SECURITY_WORKFLOW_ZIZMOR_CONFIG"
      return 2
    fi
  else
    config_path="$SECURITY_WORKFLOW_REPORTS_DIR/zizmor.yml"
    security_workflow_write_default_zizmor_config "$config_path"
  fi

  set +e
  docker run --rm \
    -v "$SECURITY_WORKFLOW_REPO:/repo:ro" \
    -v "$config_path:/zizmor.yml:ro" \
    -w /repo \
    "${docker_env[@]}" \
    "$(security_workflow_zizmor_docker_image)" \
    --config /zizmor.yml \
    --persona=regular \
    --min-severity=high \
    --min-confidence=medium \
    . 2>&1 | tee "$SECURITY_WORKFLOW_REPORTS_DIR/zizmor.txt"

  local status="${PIPESTATUS[0]}"
  set -e

  if [[ "$status" -eq 0 || "$status" -eq 3 ]]; then
    return 0
  fi

  return "$status"
}

security_workflow_docker_build() {
  security_workflow_require_docker || return $?

  local build_args=()
  local arg
  while IFS= read -r arg; do
    [[ -z "$arg" ]] && continue
    build_args+=(--build-arg "$arg")
  done <<< "$SECURITY_WORKFLOW_DOCKER_BUILD_ARGS"

  docker build \
    -f "$SECURITY_WORKFLOW_DOCKERFILE_PATH" \
    -t "$SECURITY_WORKFLOW_DOCKER_IMAGE_REF" \
    ${build_args+"${build_args[@]}"} \
    "$SECURITY_WORKFLOW_DOCKER_BUILD_CONTEXT"

  echo "$SECURITY_WORKFLOW_DOCKER_IMAGE_REF" > "$SECURITY_WORKFLOW_REPORTS_DIR/docker-image-ref.txt"
}

security_workflow_trivy_image() {
  security_workflow_require_docker || return $?

  docker run --rm \
    -e TRIVY_LIMIT_SEVERITIES_FOR_SARIF=true \
    -v "$SECURITY_WORKFLOW_REPORTS_DIR:/reports" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "$(security_workflow_trivy_docker_image)" \
    image "$SECURITY_WORKFLOW_DOCKER_IMAGE_REF" \
    --skip-version-check \
    --scanners vuln \
    --pkg-types os,library \
    --severity "$SECURITY_WORKFLOW_SECURITY_VULNERABILITY_SEVERITIES" \
    --ignore-unfixed \
    --exit-code 1 \
    --format sarif \
    --output /reports/trivy-image.sarif
}

security_workflow_trivy_license() {
  security_workflow_require_docker || return $?

  local skip_args=()
  local skip_arg
  while IFS= read -r -d '' skip_arg; do
    skip_args+=("$skip_arg")
  done < <(security_workflow_trivy_skip_args)

  docker run --rm \
    -v "$SECURITY_WORKFLOW_REPO:/repo:ro" \
    -v "$SECURITY_WORKFLOW_REPORTS_DIR:/reports" \
    "$(security_workflow_trivy_docker_image)" \
    fs /repo \
    --skip-version-check \
    --scanners license \
    --exit-code 0 \
    --format table \
    --output /reports/trivy-license.txt \
    "${skip_args[@]}"
}

security_workflow_trivy_sbom() {
  security_workflow_require_docker || return $?

  local skip_args=()
  local skip_arg
  while IFS= read -r -d '' skip_arg; do
    skip_args+=("$skip_arg")
  done < <(security_workflow_trivy_skip_args)

  docker run --rm \
    -v "$SECURITY_WORKFLOW_REPO:/repo:ro" \
    -v "$SECURITY_WORKFLOW_REPORTS_DIR:/reports" \
    "$(security_workflow_trivy_docker_image)" \
    fs /repo \
    --skip-version-check \
    --scanners vuln \
    --exit-code 0 \
    --format cyclonedx \
    --output /reports/sbom-fs.cdx.json \
    "${skip_args[@]}"
}

security_workflow_trivy_image_sbom() {
  security_workflow_require_docker || return $?

  docker run --rm \
    -v "$SECURITY_WORKFLOW_REPORTS_DIR:/reports" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "$(security_workflow_trivy_docker_image)" \
    image "$SECURITY_WORKFLOW_DOCKER_IMAGE_REF" \
    --skip-version-check \
    --scanners vuln \
    --exit-code 0 \
    --format cyclonedx \
    --output /reports/sbom-image.cdx.json
}
