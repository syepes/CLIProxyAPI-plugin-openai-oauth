#!/bin/sh
# Exercise make's build/validation boundary without a target C toolchain.
set -eu
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
cat > "$tmp/go" <<'GO_STUB'
#!/bin/sh
set -eu
case "$1" in
  env)
    case "$2" in
      GOHOSTOS) printf '%s\n' "$TEST_HOST_GOOS" ;;
      GOHOSTARCH) printf '%s\n' "$TEST_HOST_GOARCH" ;;
      *) echo "Unexpected go env query: $2" >&2; exit 1 ;;
    esac
    ;;
  build)
    test "$GOOS/$GOARCH" = "$TEST_TARGET_GOOS/$TEST_TARGET_GOARCH"
    test "$CGO_ENABLED" = 1
    case " $* " in
      *' -buildmode=c-shared '*) ;;
      *) echo 'Plugin build must use c-shared' >&2; exit 1 ;;
    esac
    printf 'build\n' >> "$TEST_CALL_LOG"
    ;;
  run)
    if [ "$GOOS/$GOARCH" != "$TEST_HOST_GOOS/$TEST_HOST_GOARCH" ]; then
      echo "Validator would execute a $GOOS/$GOARCH binary on $TEST_HOST_GOOS/$TEST_HOST_GOARCH" >&2
      exit 1
    fi
    test "$CGO_ENABLED" = 0
    test "$#" = 8
    test "$2" = ./cmd/checklib
    test "$3" = -path
    case "$TEST_TARGET_GOOS" in darwin) ext=dylib ;; *) ext=so ;; esac
    test "$4" = "dist/$TEST_TARGET_GOOS/$TEST_TARGET_GOARCH/openai-oauth.$ext"
    test "$5" = -goos
    test "$6" = "$TEST_TARGET_GOOS"
    test "$7" = -goarch
    test "$8" = "$TEST_TARGET_GOARCH"
    printf 'run\n' >> "$TEST_CALL_LOG"
    ;;
  *) echo "Unexpected go command: $1" >&2; exit 1 ;;
esac
GO_STUB
chmod +x "$tmp/go"
run_case() {
  export TEST_HOST_GOOS="$1" TEST_HOST_GOARCH="$2"
  export TEST_TARGET_GOOS="$3" TEST_TARGET_GOARCH="$4"
  export TEST_CALL_LOG="$tmp/calls"
  : > "$TEST_CALL_LOG"
  GOOS="$3" GOARCH="$4" CGO_ENABLED=1 CC=target-only-compiler \
    "${MAKE:-make}" -s -C "$repo" build GO="$tmp/go" GOOS="$3" GOARCH="$4"
  test "$(cat "$TEST_CALL_LOG")" = "$(printf 'build\nrun')"
  printf 'Build boundary passed: host %s/%s, target %s/%s\n' "$1" "$2" "$3" "$4"
}
run_case linux amd64 freebsd amd64
run_case linux arm64 freebsd amd64
run_case darwin arm64 freebsd amd64
run_case linux amd64 linux amd64
run_case darwin arm64 darwin arm64
