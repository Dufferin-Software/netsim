#!/usr/bin/env bash
# Run every netsim test suite sequentially and summarise pass/fail.
#
# Usage:
#   tests/run_all.sh [PKG_DIR]
#
# PKG_DIR defaults to ../  (where dpkg-buildpackage drops the .debs).
# Override the suite list with SUITES="a b c" tests/run_all.sh.
# Skip suites with SKIP="scale_test policy_performance" tests/run_all.sh.

set -u
cd "$(dirname "$0")/.."

PKG_DIR="${1:-..}"
SKIP="${SKIP:-}"
LOG_DIR="${LOG_DIR:-pytest-logs}"
mkdir -p "$LOG_DIR"

# Suite -> comma-separated .deb glob list. Anything not listed defaults to
# the base policy-engine package.
declare -A PKG_MAP=(
  [ips_ids]="policy-engine-ips_*.deb"
  [ipfix]="policy-engine-ipfix_*.deb"
  [multi_node]="policy-engine_*.deb policy-node-agent_*.deb policy-controller_*.deb policy-controller-client_*.deb"
  # scale_test runs engine + agent as Docker containers (built locally as
  # policy-engine:0.1.0 / policy-node-agent:0.1.0); only the controller is
  # installed on a VM.
  [scale_test]="policy-controller_*.deb"
)
DEFAULT_PKG="policy-engine_*.deb"

# Expand space-separated globs (relative to PKG_DIR) into a comma-separated
# list of real paths. Errors if any glob matches nothing.
expand_pkgs() {
  local globs="$1" out="" pat matches m
  shopt -s nullglob
  for pat in $globs; do
    matches=( "$PKG_DIR"/$pat )
    if (( ${#matches[@]} == 0 )); then
      shopt -u nullglob
      echo "ERROR: no .deb matched $PKG_DIR/$pat" >&2
      return 1
    fi
    # If multiple match (e.g. older versions left behind), take the newest.
    m=$(ls -1t "${matches[@]}" | head -n1)
    out+="${out:+,}$m"
  done
  shopt -u nullglob
  printf '%s\n' "$out"
}

# Auto-discover suites: any tests/<name>/<name>.yaml is a suite.
if [[ -z "${SUITES:-}" ]]; then
  SUITES=""
  for d in tests/*/; do
    name="$(basename "$d")"
    [[ -f "$d/$name.yaml" ]] && SUITES+="$name "
  done
fi

declare -A RESULT
declare -A DURATION
overall=0

for suite in $SUITES; do
  if [[ " $SKIP " == *" $suite "* ]]; then
    RESULT[$suite]=SKIP
    continue
  fi

  topo="tests/$suite/$suite.yaml"
  pkg_globs="${PKG_MAP[$suite]:-$DEFAULT_PKG}"
  log="$LOG_DIR/$suite.log"

  echo
  echo "================================================================"
  echo "=== $suite"
  echo "=== topo: $topo"
  echo "=== pkg globs: $pkg_globs"
  echo "================================================================"

  start=$SECONDS
  status=PASS

  if ! pkgs=$(expand_pkgs "$pkg_globs"); then
    RESULT[$suite]=PKG_MISSING
    DURATION[$suite]=$((SECONDS - start))
    overall=1
    continue
  fi
  echo "=== resolved: $pkgs"

  if ! netsim start "$topo" 2>&1 | tee "$log"; then
    status=START_FAIL
  else
    if ! python3 -m pytest "tests/$suite/" -v \
        --install-packages "$pkgs" 2>&1 | tee -a "$log"; then
      status=FAIL
    fi
  fi

  # Always attempt teardown so the next suite starts clean.
  netsim destroy "$topo" >>"$log" 2>&1 || true

  DURATION[$suite]=$((SECONDS - start))
  RESULT[$suite]=$status
  [[ $status == PASS ]] || overall=1
done

echo
echo "================================================================"
echo "=== Summary"
echo "================================================================"
printf "%-22s %-12s %8s\n" "SUITE" "RESULT" "TIME(s)"
for suite in $SUITES; do
  printf "%-22s %-12s %8s\n" \
    "$suite" "${RESULT[$suite]:-?}" "${DURATION[$suite]:-0}"
done
echo
echo "Logs: $LOG_DIR/<suite>.log"
exit $overall
