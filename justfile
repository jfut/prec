set dotenv-load := true
set export := true
set positional-arguments := true

NAME := "prec"

default:
    @just --list

#
# clean
#

clean:
    rm -rf dist
    mkdir -p dist

clean-log:
    sudo rm -rf /var/log/prec/*.log*

#
# update
#

update: update-aqua update-go

update-aqua:
    aqua update
    aqua update-checksum --deep --prune
    aqua i -l

update-go:
    go get -t -u ./...
    go mod tidy

#
# deps
#

deps:
    go mod download

#
# dev
#

fmt:
    gofmt -w ./cmd ./internal

lint:
    golangci-lint run ./...

test:
    go test ./...

help *ARGS:
    go run ./cmd/prec {{ARGS}} --help

#
# build
#

build: clean deps
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/prec ./cmd/prec
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/precd ./cmd/precd

#
# run
#

ebpf-preflight *CMD:
    @# Verify eBPF can run, then execute the given command in the same sudo session.
    @sudo -E sh -eu -c '\
        mountpoint -q /sys/kernel/tracing || mount -t tracefs tracefs /sys/kernel/tracing; \
        mountpoint -q /sys/kernel/debug || mount -t debugfs debugfs /sys/kernel/debug; \
        seccomp=$(awk "/^Seccomp:/ {print \$2}" /proc/$$/status); \
        capeff=$(awk "/^CapEff:/ {print \$2}" /proc/$$/status); \
        caps=$(capsh --decode=$capeff 2>/dev/null || true); \
        echo "$caps" | grep -Eq "cap_bpf|cap_sys_admin" || { \
            echo "Missing capabilities required to run eBPF"; \
            echo "Required: cap_bpf (or cap_sys_admin)"; \
            echo "Current: $caps"; \
            exit 1; \
        }; \
        if [ "$seccomp" = "2" ]; then \
            echo "Seccomp is enabled (mode=2); the bpf syscall may be blocked"; \
            echo "Run on the host or start the container with seccomp=unconfined"; \
            exit 1; \
        fi; \
        "$@"' sh {{CMD}}

check-ebpf-env:
    @just ebpf-preflight true

run-daemon *ARGS: build
    just ebpf-preflight ./dist/precd {{ARGS}}

run-daemon-clean *ARGS: clean clean-log
    just run-daemon {{ARGS}}

run-cli *ARGS: build
    # Pass "$@" as-is via positional-arguments to avoid misparsing queries that include `>`.
    sudo -E ./dist/prec "$@"

#
# release
#

snapshot: deps
    goreleaser release --skip=publish --clean --snapshot

release: deps
    goreleaser release --skip=publish --clean --skip=validate
