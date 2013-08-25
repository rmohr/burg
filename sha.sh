#!/bin/bash
env printf $( echo -n "$1" | sha256sum | sed 's/ .*//; s/\(..\)/\\x\1/g') |
base64
