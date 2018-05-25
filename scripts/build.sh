#!/bin/bash

set -e

DIRNAME="$(cd "$(dirname "$BASH_SOURCE")"/..; pwd)"
NOISE="$DIRNAME"/noise-c
BUILD="$DIRNAME"/build
SRC="$DIRNAME"/src

FILES=(
  "protocol/cipherstate.c"
  "protocol/dhstate.c"
  "protocol/errors.c"
  "protocol/handshakestate.c"
  "protocol/hashstate.c"
  "protocol/internal.c"
  "protocol/names.c"
  "protocol/patterns.c"
  "protocol/randstate.c"
  "protocol/signstate.c"
  "protocol/symmetricstate.c"
  "protocol/util.c"
  "backend/ref/dh-curve448.c"
  "backend/ref/dh-newhope.c"
  "backend/ref/hash-blake2s.c"
  "backend/ref/cipher-aesgcm.c"
  "backend/ref/cipher-chachapoly.c"
  "backend/ref/dh-curve25519.c"
  "backend/ref/hash-blake2b.c"
  "backend/ref/hash-sha256.c"
  "backend/ref/hash-sha512.c"
  "backend/ref/sign-ed25519.c"
  "crypto/blake2/blake2s.c"
  "crypto/curve448/curve448.c"
  "crypto/goldilocks/src/p448/arch_32/p448.c"
  "crypto/newhope/batcher.c"
  "crypto/newhope/error_correction.c"
  "crypto/newhope/fips202.c"
  "crypto/newhope/newhope.c"
  "crypto/newhope/ntt.c"
  "crypto/newhope/poly.c"
  "crypto/newhope/precomp.c"
  "crypto/newhope/reduce.c"
  "crypto/aes/rijndael-alg-fst.c"
  "crypto/blake2/blake2b.c"
  "crypto/chacha/chacha.c"
  "crypto/donna/poly1305-donna.c"
  "crypto/ghash/ghash.c"
  "crypto/newhope/crypto_stream_chacha20.c"
  "crypto/sha2/sha256.c"
  "crypto/sha2/sha512.c"
  "crypto/ed25519/ed25519.c"
)

FILES=("${FILES[@]/#/$NOISE/src/}")
FILES+=("$SRC"/noise-stream.c)

FUNCTIONS=$(node -e 'process.stdout.write(JSON.stringify(require("'"$SRC"'/functions.json")))')

mkdir -p "$BUILD"

EMMAKEN_CFLAGS="-include $SRC/noise-stream.h" \
emcc "${FILES[@]}" \
  -Os --llvm-lto 1 --closure 1 --js-library "$SRC"/library.js \
  -I "$NOISE"/include \
  -I "$NOISE"/src \
  -I "$NOISE"/src/protocol \
  -I "$NOISE"/src/crypto/goldilocks/src/include \
  -I "$NOISE"/src/crypto/goldilocks/src/p448 \
  -I "$NOISE"/src/crypto/goldilocks/src/p448/arch_32 \
  -s SHELL_FILE="$SRC"/shell.js \
  -s ABORTING_MALLOC=0 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME="noise" \
  -s EXPORTED_FUNCTIONS="$FUNCTIONS" \
  -s NO_EXIT_RUNTIME=1 \
  -s NO_FILESYSTEM=1 \
  -s EXPORTED_RUNTIME_METHODS=[] \
  -s DEFAULT_LIBRARY_FUNCS_TO_INCLUDE=[] \
  -s WASM=1 \
  -s SINGLE_FILE=1 \
  -o "$BUILD"/noise.js
