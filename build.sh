#!/bin/sh
# Build the plugin.
#   ./build.sh           test + static linux/amd64 binary in build/<plugin id>/<plugin id>
#   ./build.sh release   all store architectures in dist/ (names expected by the Zoraxy plugin store)
set -e
cd "$(dirname "$0")"
ID=org.defilippo.zoraxy.methodfilter
NAME=methodfilter
go vet . && go test .
if [ "$1" = "release" ]; then
  rm -rf dist && mkdir dist
  for target in linux/amd64 linux/386 linux/arm linux/arm64 linux/mipsle linux/riscv64 windows/amd64; do
    os=${target%/*}; arch=${target#*/}; out="dist/${NAME}_${os}_${arch}"
    [ "$os" = windows ] && out="$out.exe"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$out" .
  done
  (cd dist && sha256sum * > SHA256SUMS)
  ls -1 dist
else
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "build/$ID/$ID" .
  "./build/$ID/$ID" -introspect > .introspect
  echo "ok: build/$ID/$ID"
fi
