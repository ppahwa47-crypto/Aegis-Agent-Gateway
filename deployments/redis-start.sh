#!/bin/sh
set -eu
# Redis 7 ACLs separate the control plane from tool runtimes. Tools can only
# read grant state and write receipts belonging to their own tool namespace.
config=/tmp/aegis-redis.conf
cat > "$config" <<EOF
bind 0.0.0.0
protected-mode yes
port 6379
dir /data
appendonly yes
appendfsync always
maxmemory 256mb
maxmemory-policy noeviction
user default off
user gateway on >$(cat /run/secrets/redis_password) ~grant:* ~receipt:gateway:* +get +set +eval +evalsha +script|load +ping +hello +client|setinfo +client|setname
user docs-tool on >$(cat /run/secrets/docs_redis_password) %R~grant:* %RW~receipt:tool:docs.read:* +get +set +eval +evalsha +script|load +ping +hello +client|setinfo +client|setname
user tickets-tool on >$(cat /run/secrets/tickets_redis_password) %R~grant:* %RW~receipt:tool:tickets.create:* +get +set +eval +evalsha +script|load +ping +hello +client|setinfo +client|setname
user exports-tool on >$(cat /run/secrets/exports_redis_password) %R~grant:* %RW~receipt:tool:exports.upload:* +get +set +eval +evalsha +script|load +ping +hello +client|setinfo +client|setname
EOF
chmod 600 "$config"
exec redis-server "$config"
