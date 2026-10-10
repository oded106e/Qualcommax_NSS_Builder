#!/bin/sh
MAC="7C:66:EF:F0:C4:3C"; IP="192.168.10.171"; IF="br-lan"; DUM="rdpsink"
SYN="tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and tcp dst port 3389 and dst host $IP"
SELF=$$
woke_at=0
trap 'woke_at=$(date +%s)' USR1
 
DEBUG="${DEBUG:-0}"
dbg() { [ "$DEBUG" = "1" ] && logger -t wakeuppc "$*"; }
dbg "start: MAC=$MAC IP=$IP IF=$IF DUM=$DUM"
 
# The sink interface lives for the whole run. Creating and deleting it on
# every hold/release raced mwan3rtmon (route copied after the interface was
# gone: "oif rdpsink: interface not found") and made ttyd log DELADDR.
sink()    { if ! ip link show $DUM >/dev/null 2>&1; then
              logger -t wakeuppc "creating sink iface $DUM"
              ip link add $DUM type bridge
              echo 1 > /proc/sys/net/ipv6/conf/$DUM/disable_ipv6 2>/dev/null
            fi
            ip link set $DUM up; }
sink
 
has()     { ip neigh show proxy | grep -qF "$IP"; }
hold()    { sink
            ip route replace $IP/32 dev $DUM
            ip neigh replace proxy $IP dev $IF
            dbg "hold(): holding proxy-ARP for $IP on $IF"; }
release() { dbg "release(): releasing proxy-ARP for $IP"
            ip neigh del proxy $IP dev $IF 2>/dev/null
            ip route del $IP/32 dev $DUM 2>/dev/null; }
wake()    { dbg "wake(): invoked"
            has && { dbg "wake(): proxy-ARP was held, releasing"; release; }
            kill -USR1 "$SELF"
            dbg "wake(): sending WoL to $MAC via $IF"
            etherwake -b -i $IF $MAC; }
 
killtree() {
    for pid in /proc/[0-9]*; do
        p=${pid#/proc/}
        [ -r "$pid/stat" ] || continue
        ppid=$(awk '{print $4}' "$pid/stat" 2>/dev/null)
        [ "$ppid" = "$1" ] || continue
        killtree "$p"
        kill -TERM "$p" 2>/dev/null
    done
}
 
# procd puts the whole service (this shell, its loops, every tcpdump) in one
# cgroup, but on stop it signals only this PID. Kill the rest of the cgroup,
# so nothing is left behind to fight the next instance.
cleanup() {
    trap - TERM INT USR1
    dbg "stopping: releasing state and killing child processes"
    has && release
    ip link delete $DUM 2>/dev/null
    cg=$(sed -n 's/^0:://p' /proc/$SELF/cgroup 2>/dev/null)
    case "$cg" in
      /services/*)
        pids=""
        for p in $(cat "/sys/fs/cgroup$cg/cgroup.procs" 2>/dev/null); do
            [ "$p" = "$SELF" ] && continue
            kill -TERM "$p" 2>/dev/null && pids="$pids $p"
        done
        # Stay alive until they are gone: procd removes the cgroup as soon
        # as this PID exits, and fails ("busy cgroup") if any are left.
        for i in 1 2 3; do
            alive=""
            for p in $pids; do kill -0 "$p" 2>/dev/null && alive="$alive $p"; done
            [ -z "$alive" ] && break
            sleep 1
        done
        [ -n "$alive" ] && kill -KILL $alive 2>/dev/null ;;
      *) killtree "$SELF" ;;
    esac
    exit 0
}
trap cleanup TERM INT
 
# RDP SYN from VPN or LAN -> wake if the PC is not answering
for i in wg0 $IF; do
  dbg "starting SYN watcher on $i"
  tcpdump -i $i -n -l -q "$SYN" 2>/dev/null | while read l; do dbg "RDP SYN seen on $i"; wake; done &
done
 
# PC woke on its own (power button, keyboard...) -> stop impersonating it.
# Also start the 60 s grace period, so a PC that is up but does not answer
# ping cannot flap hold/release every few seconds.
dbg "starting self-wake watcher on $IF"
while :; do
  if has; then
    tcpdump -i $IF -n -c1 -q "ether src $MAC" >/dev/null 2>&1 && has && {
      logger -t wakeuppc "PC $IP is sending traffic while held - releasing (does it answer ping?)"
      release
      kill -USR1 "$SELF"
    }
  else
    sleep 1
  fi
done &
 
# PC silent for ~12s (and not just woken) -> answer ARP in its name.
# Waits run as "cmd & wait": ash defers a trap until a foreground command
# ends, but interrupts "wait" at once, so procd's SIGTERM is never ignored.
dbg "starting silence watcher for $IP"
f=0
while :; do
  if has; then
    sleep 4 & wait $!
  elif [ $(( $(date +%s) - woke_at )) -lt 60 ]; then
    f=0
    ping -c2 -i2 $IP >/dev/null 2>&1 & wait $!
  else
    ip neigh del $IP dev $IF 2>/dev/null
    ping -c2 -i2 -W2 $IP >/dev/null 2>&1 & wait $!
    if [ $? -eq 0 ] && ip neigh show $IP dev $IF | grep -qE 'REACH|STALE'; then
      f=0
    else
      f=$((f+1))
      dbg "PC not responding ($f/4)"
      if [ $f -ge 4 ]; then
        dbg "PC silent for ~12s, holding proxy-ARP"
        hold
        f=0
      fi
    fi
  fi
done
