#!/bin/bash

SRC="$1"
DEST="$2"

tar -czf "${DEST}" -C "$SRC" .

