#!/bin/sh
# Brings the submodules to the commits this checkout pins and stops the deploy
# if they are not there. Run from the repo root after `git pull`.
#
# `git submodule sync` first: .gitmodules can change a submodule's URL (nostrdb
# moved to arkin0x/nostrdb), and without the sync `update` keeps fetching from
# the old URL, fails to find the pinned commit, and leaves the old nostrdb in
# place for `docker compose up --build` to build.
set -eu

git submodule sync --recursive
git submodule update --init --recursive

path=server/db/nostrdb/c/nostrdb
want=$(git rev-parse "HEAD:$path")
status=$(git submodule status --recursive)
echo "$status"

# A leading '-' is not checked out, '+' is at a different commit than pinned,
# 'U' has merge conflicts.
if echo "$status" | grep -q '^[-+U]'; then
	echo "submodules are not at their pinned commits; stopping" >&2
	exit 1
fi
got=$(git -C "$path" rev-parse HEAD)
if [ "$got" != "$want" ]; then
	echo "nostrdb is at $got, this checkout pins $want; stopping" >&2
	exit 1
fi
echo "nostrdb at $want"
