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
  [ips_ids]="policy-engine-ips_*.deb policy-engine-client_*.deb"
  [ipfix]="policy-engine-ipfix_*.deb policy-engine-client_*.deb"
  [multi_node]="policy-engine_*.deb policy-engine-client_*.deb policy-node-agent_*.deb policy-controller_*.deb policy-controller-client_*.deb"
  [rotation]="policy-engine_*.deb policy-engine-client_*.deb policy-node-agent_*.deb policy-controller_*.deb policy-controller-client_*.deb"
  # scale_test runs engine + agent as Docker containers (built locally as
  # policy-engine:0.1.0 / policy-node-agent:0.1.0); only the controller is
  # installed on a VM.
  [scale_test]="policy-controller_*.deb policy-controller-client_*.deb"
)
# Default: base engine + CLI client. The CLI client is needed by most
# test helpers (lib/policy_engine/engine/cli/client.py shells out to it).
DEFAULT_PKG="policy-engine_*.deb policy-engine-client_*.deb"

# Debug-symbol and -dev/-doc packages we never want pulled into a test VM,
# even if a glob accidentally matches them.
_pkg_excluded() {
  case "$1" in
    *-dbgsym_*.deb|*-dev_*.deb|*-doc_*.deb) return 0 ;;
    *) return 1 ;;
  esac
}

# Expand space-separated globs (relative to PKG_DIR) into a comma-separated
# list of real paths. Errors if any glob matches nothing.
expand_pkgs() {
  local globs="$1" out="" pat matches kept m
  # Split the glob list into patterns with pathname expansion OFF -- otherwise
  # the patterns would expand against the *current* directory here, and with
  # nullglob (set below) a non-match deletes them entirely before we ever
  # reach the "$PKG_DIR"/$pat expansion, leaving us with an empty result.
  local -a pats
  set -f; pats=( $globs ); set +f
  shopt -s nullglob
  for pat in "${pats[@]}"; do
    matches=( "$PKG_DIR"/$pat )
    # Drop dbgsym/dev/doc variants so a loose glob can't drag them in.
    kept=()
    for m in "${matches[@]}"; do
      _pkg_excluded "$(basename "$m")" || kept+=( "$m" )
    done
    if (( ${#kept[@]} == 0 )); then
      shopt -u nullglob
      echo "ERROR: no .deb matched $PKG_DIR/$pat" >&2
      return 1
    fi
    # If multiple match (e.g. older versions left behind), take the newest.
    m=$(ls -1t "${kept[@]}" | head -n1)
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
declare -A COUNTS
overall=0
current_topo=""
interrupted=0

on_interrupt() {
  interrupted=1
  echo
  echo "=== interrupted, cleaning up..." >&2
  if [[ -n "$current_topo" ]]; then
    netsim destroy "$current_topo" >>"${current_log:-/dev/null}" 2>&1 || true
  fi
  trap - INT
  # Re-raise so the exit status reflects the signal.
  kill -INT $$
}
trap on_interrupt INT

for suite in $SUITES; do
  if [[ " $SKIP " == *" $suite "* ]]; then
    RESULT[$suite]=SKIP
    continue
  fi

  topo="tests/$suite/$suite.yaml"
  pkg_globs="${PKG_MAP[$suite]:-$DEFAULT_PKG}"
  log="$LOG_DIR/$suite.log"
  current_topo="$topo"
  current_log="$log"

  echo
  echo "================================================================"
  echo "=== $suite"
  echo "=== topo: $topo"
  echo "=== pkg globs: $pkg_globs"
  echo "================================================================"

  start=$SECONDS
  status=PASS

  # expand_pkgs errors (rc 1) on a glob that matches nothing. The extra
  # empty-string guard is belt-and-suspenders: an empty --install-packages
  # silently installs nothing and skips every package-dependent test, which
  # would otherwise be misreported as a pass.
  if pkgs=$(expand_pkgs "$pkg_globs") && [[ -z "$pkgs" ]]; then
    echo "ERROR: expand_pkgs returned no packages for '$pkg_globs'" >&2
  fi
  if [[ -z "$pkgs" ]]; then
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
    # Pull the pass/fail/skip counts out of pytest's final summary line
    # (e.g. "==== 1 failed, 2 passed, 3 skipped in 4.56s ===="). A suite can
    # exit 0 while skipping every test, so the counts matter beyond PASS/FAIL.
    summary_line=$(grep -E '^=+ .*(passed|failed|skipped|error|no tests ran)' \
      "$log" | tail -n1)
    if [[ -n "$summary_line" ]]; then
      counts=""
      for kind in failed passed skipped error errors xfailed deselected; do
        n=$(grep -oE "[0-9]+ $kind\b" <<<"$summary_line" | grep -oE '^[0-9]+')
        [[ -n "$n" ]] && counts+="${counts:+, }$n $kind"
      done
      COUNTS[$suite]="$counts"
      # Surface a suite that passed-but-skipped-everything: if there were
      # skips and nothing actually passed, it didn't really test anything.
      if [[ $status == PASS && "$summary_line" != *" passed"* \
            && "$summary_line" == *" skipped"* ]]; then
        status=ALL_SKIPPED
      fi
    fi
  fi

  # Always attempt teardown so the next suite starts clean.
  netsim destroy "$topo" >>"$log" 2>&1 || true

  DURATION[$suite]=$((SECONDS - start))
  RESULT[$suite]=$status
  current_topo=""
  current_log=""
  # ALL_SKIPPED is reported but, like an explicit SKIP, doesn't fail the run.
  case "$status" in PASS|ALL_SKIPPED) ;; *) overall=1 ;; esac
done

summary_log="$LOG_DIR/summary.log"
{
  echo
  echo "================================================================"
  echo "=== Summary"
  echo "================================================================"
  printf "%-22s %-12s %8s  %s\n" "SUITE" "RESULT" "TIME(s)" "TESTS"
  for suite in $SUITES; do
    printf "%-22s %-12s %8s  %s\n" \
      "$suite" "${RESULT[$suite]:-?}" "${DURATION[$suite]:-0}" \
      "${COUNTS[$suite]:-}"
  done

  # Call out anything that didn't cleanly pass so failures/skips are easy to
  # spot (and grep) in the persisted log. ALL_SKIPPED and SKIP both count as
  # skips; everything else non-PASS is a failure.
  failed="" skipped=""
  for suite in $SUITES; do
    case "${RESULT[$suite]:-?}" in
      PASS)              ;;
      SKIP|ALL_SKIPPED)  skipped+="$suite (${RESULT[$suite]}) " ;;
      *)                 failed+="$suite (${RESULT[$suite]:-?}) " ;;
    esac
  done
  echo
  [[ -n "$failed" ]]  && echo "FAILED:  $failed"  || echo "FAILED:  none"
  [[ -n "$skipped" ]] && echo "SKIPPED: $skipped" || echo "SKIPPED: none"
  echo
  echo "Logs: $LOG_DIR/<suite>.log"
} | tee "$summary_log"

exit $overall
