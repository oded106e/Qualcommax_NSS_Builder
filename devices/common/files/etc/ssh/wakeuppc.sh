#!/bin/sh
MAC="7C:66:EF:F0:C4:3C"; IP="192.168.10.171"; IF="br-lan"; DUM="rdpsink"
SYN="tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and tcp dst port 3389 and dst host $IP"
SELF=$$
woke_at=0
trap 'woke_at=$(date +%s)' USR1

DEBUG="${DEBUG:-0}"
dbg() { [ "$DEBUG" = "1" ] && logger -t wakeuppc "$*"; }
dbg "start: MAC=$MAC IP=$IP IF=$IF DUM=$DUM"

has()     { ip neigh show proxy | grep -qF "$IP"; }
hold()    { if ip link show $DUM >/dev/null 2>&1; then
              dbg "hold(): dummy iface $DUM already exists"
            else
              dbg "hold(): creating dummy iface $DUM"
              ip link add $DUM type bridge; ip link set $DUM up
            fi
            ip route replace $IP/32 dev $DUM
            ip neigh replace proxy $IP dev $IF
            dbg "hold(): holding proxy-ARP for $IP on $IF"; }
release() { dbg "release(): releasing proxy-ARP for $IP"
            ip neigh del proxy $IP dev $IF 2>/dev/null
            ip route del $IP/32 dev $DUM 2>/dev/null
            ip link delete $DUM 2>/dev/null; }
up()      { ip neigh del $IP dev $IF 2>/dev/null
            ping -c1 -W2 $IP >/dev/null 2>&1
            ip neigh show $IP dev $IF | grep -qE 'REACH|STALE'; }
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

cleanup() {
    dbg "stopping: releasing state and killing child processes"
    has && release
    killtree "$SELF"
    exit 0
}
trap cleanup TERM INT

# RDP SYN from VPN or LAN -> wake if the PC is not answering
for i in wg0 $IF; do
  dbg "starting SYN watcher on $i"
  tcpdump -i $i -n -l -q "$SYN" 2>/dev/null | while read l; do dbg "RDP SYN seen on $i"; wake; done &
done

# PC woke up on its own (power button, keyboard...) -> stop impersonating it
dbg "starting self-wake watcher on $IF"
while :; do
  if has; then
    tcpdump -i $IF -n -c1 -q "ether src $MAC" >/dev/null 2>&1 && has && { dbg "PC woke on its own"; release; }
  else
    ping -c2 -i1 127.0.0.1 >/dev/null 2>&1
  fi
done &

# PC silent for ~12s (and not just woken) -> answer ARP in its name
dbg "starting silence watcher for $IP"
f=0
while :; do
  if has; then
    ping -c2 -i2 127.0.0.1 >/dev/null 2>&1
  elif [ $(( $(date +%s) - woke_at )) -lt 60 ]; then
    f=0
    ping -c2 -i2 $IP >/dev/null 2>&1
  else
    ip neigh del $IP dev $IF 2>/dev/null
    if ping -c2 -i2 -W2 $IP >/dev/null 2>&1 && ip neigh show $IP dev $IF | grep -qE 'REACH|STALE'; then
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
