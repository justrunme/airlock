#!/bin/sh
# Remove sandbox leftovers. Receipts are never pruned: deleting one breaks the chain.
set -eu
DATA="${AIRLOCK_DATA_DIR:-/var/lib/airlock}"
MAX_AGE_S="${AIRLOCK_PRUNE_AGE_S:-600}"
now=$(date +%s)

# containers named airlock-* older than MAX_AGE_S (normal runs remove themselves in seconds)
docker ps -a --filter name=^airlock- --format '{{.ID}} {{.CreatedAt}}' | while read -r id created; do
  ts=$(date -d "$(echo "$created" | awk '{print $1" "$2" "$3}')" +%s 2>/dev/null || echo "$now")
  if [ $((now - ts)) -gt "$MAX_AGE_S" ]; then
    docker rm -f "$id" >/dev/null && echo "removed container $id"
  fi
done

# networks created for sandboxes, if any were left behind
docker network ls --filter name=^airlock- --format '{{.ID}}' | while read -r id; do
  docker network rm "$id" >/dev/null 2>&1 && echo "removed network $id" || true
done

# work dirs older than 10 minutes
if [ -d "$DATA/work" ]; then
  find "$DATA/work" -mindepth 1 -maxdepth 1 -mmin +10 -exec rm -rf {} + -print
fi
