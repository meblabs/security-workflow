#!/usr/bin/env bash
# Gate outcome is intentionally written for the entrypoint and GitHub outputs.
# shellcheck disable=SC2034

security_workflow_check_required() {
  local name="$1"
  local outcome="$2"
  local applicable="$3"

  if [[ "$applicable" != "true" ]]; then
    echo "$(security_workflow_skip_label): ${name} is not applicable."
    return 0
  fi

  case "$outcome" in
    success)
      echo "$(security_workflow_pass_label): ${name}"
      return 0
      ;;
    failure|cancelled|timed_out|action_required)
      echo "$(security_workflow_fail_label): ${name} ended with outcome '${outcome}'."
      return 1
      ;;
    skipped)
      echo "$(security_workflow_fail_label): ${name} was skipped but is applicable."
      return 1
      ;;
    *)
      echo "$(security_workflow_fail_label): ${name} has unknown outcome '${outcome:-empty}'."
      return 1
      ;;
  esac
}

security_workflow_gate() {
  local failed=0

  security_workflow_check_required "Semgrep SAST" "$SEMGREP_OUTCOME" "true" || failed=1
  security_workflow_check_required "Gitleaks secrets" "$GITLEAKS_OUTCOME" "true" || failed=1
  security_workflow_check_required "Trivy filesystem SCA" "$TRIVY_FS_OUTCOME" "true" || failed=1
  security_workflow_check_required "Trivy IaC/config misconfiguration" "$TRIVY_CONFIG_OUTCOME" "true" || failed=1
  security_workflow_check_required "cfn-lint SAM/CloudFormation validation" "$CFN_LINT_OUTCOME" "$SAM_TEMPLATES" || failed=1
  security_workflow_check_required "zizmor GitHub Actions security" "$ZIZMOR_OUTCOME" "$GITHUB_ACTIONS_FILES" || failed=1
  security_workflow_check_required "Docker image build" "$DOCKER_BUILD_OUTCOME" "$ROOT_DOCKERFILE" || failed=1
  security_workflow_check_required "Trivy Docker image scan" "$TRIVY_IMAGE_OUTCOME" "$ROOT_DOCKERFILE" || failed=1

  if [[ "$failed" -ne 0 ]]; then
    SECURITY_GATE_OUTCOME="failure"
    echo "$(security_workflow_fail_label): Security gate failed."
    return 1
  fi

  SECURITY_GATE_OUTCOME="success"
  echo "$(security_workflow_pass_label): Security gate passed."
  return 0
}
