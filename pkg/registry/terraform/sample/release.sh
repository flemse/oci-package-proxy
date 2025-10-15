#!/bin/sh

# Parse arguments
while [ $# -gt 0 ]; do
  case "$1" in
    --dist-path)
      DIST_DIR="$2"
      shift 2
      ;;
    --upload-url)
      UPLOAD_URL="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [ -z "$DIST_DIR" ] || [ -z "$UPLOAD_URL" ]; then
  echo "Usage: $0 --dist-path=<dist_dir> --upload-url=<url>"
  exit 1
fi

SHASUM_FILE=$(ls "$DIST_DIR" | grep SHA256SUMS | head -1)
SIG_FILE=$(ls "$DIST_DIR" | grep SHA256SUMS.sig | head -1)
VERSION=$(echo "$SHASUM_FILE" | sed -e 's/^[^_]*_\([^_]*\)_SHA256SUMS$/\1/')
ZIP_FILES=$(grep '\.zip$' "$DIST_DIR/$SHASUM_FILE" | awk '{print $2}')
CURL_ARGS="-F namespace=test -F type=sample-provider -F version=$VERSION"
CURL_ARGS="$CURL_ARGS -F SHA256SUMS=@$DIST_DIR/$SHASUM_FILE"

# Add signature file if it exists
if [ -n "$SIG_FILE" ] && [ -f "$DIST_DIR/$SIG_FILE" ]; then
  CURL_ARGS="$CURL_ARGS -F SHA256SUMS.sig=@$DIST_DIR/$SIG_FILE"
fi

for zipfile in $ZIP_FILES; do
  CURL_ARGS="$CURL_ARGS -F $zipfile=@$DIST_DIR/$zipfile"
done

curl -v -X POST $CURL_ARGS "$UPLOAD_URL"
