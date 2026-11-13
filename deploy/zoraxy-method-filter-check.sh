#!/bin/bash
# Optional watchdog for the "HTTP Method Filter" Zoraxy plugin (run it from cron, e.g. every 5 minutes).
#
# Zoraxy fails open: when a plugin crashes it is disabled and requests are forwarded
# unfiltered. This script probes a filtered host with a made-up method; if the answer
# is not the refusal you configured, it logs to syslog and runs a command of your
# choice to re-enable the plugin (Zoraxy has no unauthenticated API for that, so the
# command is yours to provide: an API call with a session, or a Zoraxy restart).
#
# Configuration (environment, or edit the defaults below):
#   MF_URL       URL of a host that has the filter enabled      (required)
#   MF_RESOLVE   optional curl --resolve value, e.g. "app.example.com:443:127.0.0.1"
#   MF_EXPECT    status the plugin answers for refused requests (default 405)
#   MF_REPAIR    command that re-enables the plugin             (optional)
MF_URL=${MF_URL:?set MF_URL to a filtered host, e.g. https://app.example.com/}
MF_EXPECT=${MF_EXPECT:-405}
TAG=zoraxy-method-filter

probe() {
  curl -s -o /dev/null -m 10 -w "%{http_code}" -X ZZCHECK ${MF_RESOLVE:+--resolve "$MF_RESOLVE"} "$MF_URL"
}

code=$(probe)
[ "$code" = "$MF_EXPECT" ] && exit 0
[ "$code" = "000" ] && exit 0          # proxy unreachable: not a plugin problem

logger -t $TAG -p daemon.warning "filter NOT active (probe method answered $code instead of $MF_EXPECT)"
[ -n "$MF_REPAIR" ] || exit 1
sh -c "$MF_REPAIR" >/dev/null 2>&1
sleep 5
code=$(probe)
if [ "$code" = "$MF_EXPECT" ]; then
  logger -t $TAG -p daemon.notice "plugin re-enabled, filter active again"
else
  logger -t $TAG -p daemon.err "plugin NOT restored (probe method answered $code): manual action needed"
  exit 1
fi
