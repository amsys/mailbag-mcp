#!/bin/sh
# scripts/coverage_gate.sh: fail when the total coverage is under the limit.
# usage: scripts/coverage_gate.sh cover.out [limit]   (default limit 80.0)
# CI (test.yml, Linux job) and a person run this same script.
# Exit 0 at or above the limit, 1 below it, 2 on a usage or input error.
# arch: DS10.1, DS10.8, DS10.13, IS10.7
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	echo "usage: $0 cover.out [limit]" >&2
	exit 2
fi
profile=$1
limit=${2:-80.0}

case $limit in
'' | *[!0-9.]* | *.*.* | .* | *.)
	echo "coverage_gate: limit must be a number, got '$limit'" >&2
	exit 2
	;;
esac

if ! report=$(go tool cover -func="$profile"); then
	echo "coverage_gate: go tool cover failed on '$profile'" >&2
	exit 2
fi

total=$(printf '%s\n' "$report" | awk '$1 == "total:" { sub(/%$/, "", $NF); print $NF }')
case $total in
'' | *[!0-9.]*)
	echo "coverage_gate: no total: line in '$profile'" >&2
	exit 2
	;;
esac

echo "coverage $total % (limit $limit %)"
awk -v t="$total" -v l="$limit" 'BEGIN { exit !(t + 0 >= l + 0) }' || exit 1
