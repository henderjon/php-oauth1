#!/bin/sh
set -e
cd "$(dirname "$0")"

php -S 127.0.0.1:8091 -t tool-consumer &
php -S 127.0.0.1:8092 -t tool-provider &

trap 'kill $(jobs -p) 2>/dev/null' EXIT INT TERM

wait
