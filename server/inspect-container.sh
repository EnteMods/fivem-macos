#!/bin/sh
# Read-only Docker state inspection; this is not a security or health check.
set -eu
if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  printf 'Usage: %s <container-name-or-id>\n' "$0" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  printf 'Docker CLI not found.\n' >&2
  exit 1
fi
# A single format expression avoids displaying environment, mounts or secrets.
docker inspect --type container --format 'Running={{.State.Running}} OpenStdin={{.Config.OpenStdin}} RestartPolicy={{.HostConfig.RestartPolicy.Name}}' -- "$1"
printf '%s\n' 'This does not verify firewall rules, server health, authentication or gameplay.'
