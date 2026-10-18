#!/bin/sh
# Release gate: check a v* tag before CI builds it, and write the release
# notes. The tag must have a good SSH signature from a key in the allowed
# signers file, its commit must be on main, and CHANGELOG.md must have a
# section for its version. That section goes to the notes file.
# A tag that a leaked token pushes has no good signature, so it stops here.
# This is true only when the copy of this script and of the allowed
# signers file that runs comes from main, not from the tag: a tag can hold
# any tree. release.yml reads both files from origin/main for this reason.
# arch: DS12.7, IS12.5, DF.1, DF.3
#
# Usage:
#   verify-tag.sh [--allowed-signers FILE] [--main REF] [--changelog FILE]
#                 [--notes FILE] [--commit SHA] TAG
#   verify-tag.sh --selftest
#
# Run it from the top directory of the clone. The defaults are
# .github/allowed_signers, origin/main, CHANGELOG.md and dist-notes.md.
# With --commit, the tag must point to that commit. CI gives the commit
# that it checked out and builds, so a tag ref that moves after the
# checkout fails.
# Exit status: 0 when all checks pass, 1 when a check fails, 2 on a usage
# error.

set -eu

fail() {
	printf 'verify-tag: %s\n' "$*" >&2
	exit 1
}

usage() {
	printf 'usage: verify-tag.sh [--allowed-signers FILE] [--main REF] [--changelog FILE] [--notes FILE] [--commit SHA] TAG\n       verify-tag.sh --selftest\n' >&2
	exit 2
}

# verify runs the checks on one tag. The arguments are the same as those
# of the script, without --selftest.
verify() {
	signers=.github/allowed_signers
	main_ref=origin/main
	changelog=CHANGELOG.md
	notes=dist-notes.md
	want_commit=
	tag=
	while [ $# -gt 0 ]; do
		case $1 in
		--allowed-signers) [ $# -ge 2 ] || usage; signers=$2; shift 2 ;;
		--main) [ $# -ge 2 ] || usage; main_ref=$2; shift 2 ;;
		--changelog) [ $# -ge 2 ] || usage; changelog=$2; shift 2 ;;
		--notes) [ $# -ge 2 ] || usage; notes=$2; shift 2 ;;
		--commit) [ $# -ge 2 ] || usage; want_commit=$2; shift 2 ;;
		-*) usage ;;
		*) [ -z "$tag" ] || usage; tag=$1; shift ;;
		esac
	done
	[ -n "$tag" ] || usage

	# 1. The tag name is v and a semantic version.
	printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' ||
		fail "tag $tag is not v<major>.<minor>.<patch>[-<pre>]"
	version=${tag#v}

	# 2. The tag is an annotated tag with a good SSH signature from a key
	# in the allowed signers file. A lightweight tag has no signature.
	[ -s "$signers" ] || fail "allowed signers file $signers is missing or empty"
	[ "$(git cat-file -t "refs/tags/$tag" 2>/dev/null)" = tag ] ||
		fail "tag $tag is not an annotated tag; make it with git tag -s"
	git -c gpg.ssh.allowedSignersFile="$signers" verify-tag "$tag" ||
		fail "tag $tag has no good signature from a key in $signers"

	# 3. The name in the signed tag object is the name of the ref. Without
	# this check, a ref v9.9.9 that points to the signed tag object of
	# an older version passes the signature check.
	name=$(git cat-file tag "refs/tags/$tag" | sed -n 's/^tag //p' | head -n 1)
	[ "$name" = "$tag" ] ||
		fail "ref $tag points to the signed tag object of $name"

	# 4. The commit of the tag is the expected commit, when given, and it
	# is on main.
	commit=$(git rev-parse --verify "refs/tags/$tag^{commit}") ||
		fail "tag $tag points to no commit"
	if [ -n "$want_commit" ]; then
		want=$(git rev-parse --verify --quiet "$want_commit^{commit}") ||
			fail "commit $want_commit does not exist"
		[ "$commit" = "$want" ] ||
			fail "tag $tag points to $commit, not to the commit $want"
	fi
	git rev-parse --verify --quiet "$main_ref^{commit}" >/dev/null ||
		fail "main ref $main_ref does not exist"
	git merge-base --is-ancestor "$commit" "$main_ref" ||
		fail "commit $commit of tag $tag is not on $main_ref"

	# 5. CHANGELOG.md has a section "## [<version>]" with text in it.
	# The section ends at the next "## " heading.
	[ -f "$changelog" ] || fail "changelog $changelog is missing"
	awk -v head="## [$version]" '
		index($0, head) == 1 {
			rest = substr($0, length(head) + 1)
			if (rest == "" || substr(rest, 1, 1) == " ") { found = 1; next }
		}
		found && /^## / { exit }
		found { print }
	' "$changelog" >"$notes"
	grep -q '[^[:space:]]' "$notes" ||
		fail "$changelog has no section \"## [$version]\" with text in it"

	printf 'verify-tag: tag %s is signed, on %s, and has notes in %s\n' \
		"$tag" "$main_ref" "$notes"
}

# expect runs the script on a case of the self-test. It compares the exit
# status with the expected one, and it finds the expected text in the
# error output, so that each case fails for its own reason.
expect() {
	want=$1
	reason=$2
	name=$3
	shift 3
	got=0
	sh "$self" "$@" >/dev/null 2>"$work/stderr" || got=$?
	if [ "$got" -ne "$want" ]; then
		printf 'FAIL %s: exit %s, want %s\n' "$name" "$got" "$want"
		failures=$((failures + 1))
	elif ! grep -qF -- "$reason" "$work/stderr"; then
		printf 'FAIL %s: error output has no "%s":\n%s\n' "$name" "$reason" "$(cat "$work/stderr")"
		failures=$((failures + 1))
	else
		printf 'ok   %s\n' "$name"
	fi
}

# selftest makes a repository with two throwaway SSH keys in a temporary
# directory and runs the checks on good and bad tags. It does not use the
# git configuration, the keys or the ssh-agent of the user.
selftest() {
	command -v ssh-keygen >/dev/null || fail "selftest needs ssh-keygen"
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT HUP INT TERM
	failures=0

	# Isolate git from the configuration of the user.
	GIT_CONFIG_GLOBAL=/dev/null
	GIT_CONFIG_NOSYSTEM=1
	export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM
	unset SSH_AUTH_SOCK GIT_DIR GIT_WORK_TREE

	ssh-keygen -q -t ed25519 -N '' -C good -f "$work/good"
	ssh-keygen -q -t ed25519 -N '' -C bad -f "$work/bad"
	printf 'dev@example.org namespaces="git" %s\n' "$(cat "$work/good.pub")" >"$work/allowed_signers"

	repo=$work/repo
	git init -q -b main "$repo"
	cd "$repo"
	git config user.name 'Self Test'
	git config user.email dev@example.org
	git config gpg.format ssh
	git config user.signingkey "$work/good"
	mkdir .github
	cp "$work/allowed_signers" .github/allowed_signers
	cat >CHANGELOG.md <<'EOF'
# Changelog

## [Unreleased]

## [1.2.0] - 2026-10-19

### Added

- Feature one.

## [1.1.0] - 2026-10-01

- Old text.

## [1.3.0]
EOF
	git add .
	git commit -q -m 'chore: first commit'
	git tag -s -m v1.2.0 v1.2.0
	git tag -a -m 'no signature' v1.2.1
	git tag v1.2.2
	git -c user.signingkey="$work/bad" tag -s -m 'other key' v1.2.3
	git tag -s -m 'no changelog section' v1.4.0
	git tag -s -m 'empty changelog section' v1.3.0
	git tag -s -m 'bad name' release-1.2.0
	# A ref v1.5.0 that points to the signed tag object of v1.2.0.
	git update-ref refs/tags/v1.5.0 "$(git rev-parse refs/tags/v1.2.0)"
	first=$(git rev-parse HEAD)
	git switch -q -c side
	git commit -q --allow-empty -m 'chore: not on main'
	git tag -s -m 'not on main' v1.2.4
	side=$(git rev-parse HEAD)
	git switch -q main

	expect 0 'Good "git" signature' 'signed tag on main with a section passes' --main main v1.2.0
	# The x at the end keeps the trailing newlines in the comparison.
	expected=$(printf '\n### Added\n\n- Feature one.\n\nx')
	if [ "$(cat dist-notes.md; printf x)" = "$expected" ]; then
		printf 'ok   notes hold the section of 1.2.0 only\n'
	else
		printf 'FAIL notes hold the section of 1.2.0 only: got:\n%s\n' "$(cat dist-notes.md)"
		failures=$((failures + 1))
	fi
	expect 0 'Good "git" signature' 'tag on the given commit passes' --main main --commit "$first" v1.2.0
	expect 1 'has no good signature' 'annotated tag with no signature fails' --main main v1.2.1
	expect 1 'not an annotated tag' 'lightweight tag fails' --main main v1.2.2
	expect 1 'has no good signature' 'tag signed by a key not in allowed_signers fails' --main main v1.2.3
	expect 1 'points to the signed tag object of v1.2.0' 'ref that points to the tag object of another version fails' --main main v1.5.0
	expect 1 'not to the commit' 'tag on a commit other than the given one fails' --main main --commit "$side" v1.2.0
	expect 1 'is not on main' 'tag not on main fails' --main main v1.2.4
	expect 1 'has no section' 'tag with no changelog section fails' --main main v1.4.0
	expect 1 'has no section' 'tag with an empty changelog section fails' --main main v1.3.0
	expect 1 'is not v<major>' 'tag name that is not v<semver> fails' --main main release-1.2.0
	expect 1 'does not exist' 'missing main ref fails' --main origin/main v1.2.0
	expect 1 'is missing or empty' 'empty allowed signers file fails' --main main --allowed-signers /dev/null v1.2.0
	expect 2 'usage:' 'no tag is a usage error' --main main

	if [ "$failures" -ne 0 ]; then
		printf 'verify-tag selftest: %s failures\n' "$failures"
		exit 1
	fi
	printf 'verify-tag selftest: all cases pass\n'
}

self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")

if [ "${1:-}" = --selftest ]; then
	[ $# -eq 1 ] || usage
	selftest
else
	verify "$@"
fi
