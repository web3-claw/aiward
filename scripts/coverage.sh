#!/bin/sh
set -eu

export LLVM_COV="${LLVM_COV:-/opt/homebrew/opt/llvm/bin/llvm-cov}"
export LLVM_PROFDATA="${LLVM_PROFDATA:-/opt/homebrew/opt/llvm/bin/llvm-profdata}"

cargo fmt --check
cargo check
cargo test -- --test-threads=1
cargo llvm-cov clean --workspace
cargo llvm-cov --no-report -- --test-threads=1

coverage_binary="target/llvm-cov-target/debug/envgate"
coverage_profile="target/llvm-cov-target/env-gate-manual-%p-%m.profraw"

run_coverage_help() {
  LLVM_PROFILE_FILE="$coverage_profile" "$coverage_binary" "$@" --help >/dev/null
}

run_coverage_help
run_coverage_help setup
run_coverage_help init
run_coverage_help import
run_coverage_help register
run_coverage_help use
run_coverage_help projects
run_coverage_help projects list
run_coverage_help projects show
run_coverage_help projects register
run_coverage_help projects use
run_coverage_help projects remove
run_coverage_help env
run_coverage_help env list
run_coverage_help env set
run_coverage_help env unset
run_coverage_help env unlock
run_coverage_help env lock
run_coverage_help env export
run_coverage_help request
run_coverage_help allow
run_coverage_help grants
run_coverage_help grants list
run_coverage_help grants revoke
run_coverage_help grants prune
run_coverage_help approve
run_coverage_help deny
run_coverage_help run
run_coverage_help dev
run_coverage_help migrate
run_coverage_help doctor
run_coverage_help broker
run_coverage_help broker status
run_coverage_help broker stop
run_coverage_help broker socket-path
run_coverage_help worktrees
run_coverage_help worktrees list
run_coverage_help worktrees allow-root
run_coverage_help worktrees remove-root
run_coverage_help worktrees approve
run_coverage_help worktrees deny
run_coverage_help logs
run_coverage_help logs view
run_coverage_help logs verify
run_coverage_help logs export
run_coverage_help logs unlock
run_coverage_help edit
run_coverage_help unlock
run_coverage_help lock
run_coverage_help teardown

LLVM_PROFILE_FILE="$coverage_profile" "$coverage_binary" __coverage >/dev/null

cargo llvm-cov report --fail-under-lines 100
