#!/usr/bin/env bash
# Runs the Report steps of scan.yml against hand-made scanner reports and
# checks the gate: broken reports fail, clean scans pass, severe findings fail,
# and scanner-controlled strings cannot start a workflow command or break the
# summary table. Needs bash, jq and yq (all on the GitHub-hosted runners).
#
#   test/report.sh [path/to/scan.yml]
set -uo pipefail

workflow=${1:-.github/workflows/scan.yml}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

for job in semgrep trivy; do
  yq ".jobs.$job.steps[] | select(.name == \"Report\") | .run" "$workflow" > "$work/$job.sh"
  [ -s "$work/$job.sh" ] || { echo "no Report step in job $job"; exit 1; }
done

# check <job> <expected exit> <name> <report content, or MISSING>
check() {
  local job=$1 want=$2 name=$3 content=$4 report="$work/report.json" got
  rm -f "$report"
  [ "$content" = MISSING ] || printf '%s' "$content" > "$report"
  : > "$work/summary"
  REPORT=$report FAIL_ON="CRITICAL HIGH ERROR" GITHUB_STEP_SUMMARY="$work/summary" \
    bash --noprofile --norc -eo pipefail "$work/$job.sh" > "$work/out" 2>&1
  got=$?
  if [ "$got" != "$want" ]; then
    echo "FAIL $job: $name: exit $got, expected $want"
    sed 's/^/    /' "$work/out"
    failures=$((failures + 1))
    return
  fi
  # Every workflow command must be one of the intended ::error lines.
  if grep -v '^::error ' "$work/out" | grep -q '^::'; then
    echo "FAIL $job: $name: injected workflow command"
    sed 's/^/    /' "$work/out"
    failures=$((failures + 1))
    return
  fi
  # Every summary line after the heading is blank, the count or a table row.
  if tail -n +2 "$work/summary" | grep -Ev '^$|finding\(s\)|^\|.*\|$' | grep -q .; then
    echo "FAIL $job: $name: broken summary"
    sed 's/^/    /' "$work/summary"
    failures=$((failures + 1))
    return
  fi
  echo "ok   $job: $name"
}

# Broken scanner output fails closed.
for job in semgrep trivy; do
  check "$job" 1 "missing report" MISSING
  check "$job" 1 "empty report" ""
  check "$job" 1 "not JSON" "not json"
  check "$job" 1 "empty object" "{}"
  check "$job" 1 "array" "[]"
done
check semgrep 1 "results is not a list" '{"results": null}'
check trivy 1 "Results is not a list" '{"SchemaVersion": 2, "Results": {}}'

# Clean scans pass.
check semgrep 0 "no findings" '{"results": [], "errors": []}'
check trivy 0 "nothing scanned" '{"SchemaVersion": 2}'
check trivy 0 "no findings" '{"SchemaVersion": 2, "Results": [{"Target": "package-lock.json", "Class": "lang-pkgs"}]}'

# The thresholds.
semgrep_result() { # <severity> <path>
  jq -cn --arg sev "$1" --arg path "$2" '{results: [{check_id: "rule.id", path: $path, start: {line: 3},
    extra: {severity: $sev, message: "Bad\nthing"}}], errors: []}'
}
trivy_vuln() { # <severity> <fixed version> <target> <package>
  jq -cn --arg sev "$1" --arg fix "$2" --arg target "$3" --arg pkg "$4" '{SchemaVersion: 2, Results: [{Target: $target,
    Vulnerabilities: [{VulnerabilityID: "CVE-2026-0001", PkgName: $pkg, InstalledVersion: "1.0.0",
      FixedVersion: (if $fix == "" then null else $fix end), Severity: $sev}]}]}'
}
check semgrep 1 "ERROR finding" "$(semgrep_result ERROR src/a.ts)"
check semgrep 0 "WARNING finding" "$(semgrep_result WARNING src/a.ts)"
check trivy 1 "CRITICAL with a fix" "$(trivy_vuln CRITICAL 1.0.1 package-lock.json lodash)"
check trivy 0 "CRITICAL without a fix" "$(trivy_vuln CRITICAL "" package-lock.json lodash)"
check trivy 0 "HIGH with a fix" "$(trivy_vuln HIGH 1.0.1 package-lock.json lodash)"

# Paths and package names come from the scanned repo.
evil=$'a,line=1\n::warning::injected\n`|b'
check semgrep 1 "hostile path" "$(semgrep_result ERROR "$evil")"
check trivy 1 "hostile target and package" "$(trivy_vuln CRITICAL 1.0.1 "$evil" "$evil")"
check trivy 0 "hostile values below the threshold" "$(trivy_vuln HIGH 1.0.1 "$evil" "$evil")"

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
