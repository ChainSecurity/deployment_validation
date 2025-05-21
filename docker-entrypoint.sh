#!/usr/bin/env bash
set -e

# If no arguments were given, drop into an interactive login shell:
if [ $# -eq 0 ]; then
  exec zsh -li
else
  # Otherwise, join all args into a single string and run it in a login shell:
  cmd="$*"
  exec zsh -lc "$cmd"
fi

