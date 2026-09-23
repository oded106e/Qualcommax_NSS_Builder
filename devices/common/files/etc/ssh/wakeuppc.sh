#!/bin/sh
MAC="7C:66:EF:F0:C4:3C"; IP="192.168.10.171"; IF="br-lan"; DUM="rdpsink"
SYN="tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and tcp dst port 3389 and dst host $IP"
SELF=$$
woke_at=0
trap 'woke_at=$(date +%s)' USR1

ip link show $DUM >/dev/null 2>&1 || { ip link add $DUM type bridge; ip link set $DUM up; }

has()     { ip neigh show proxy | grep -qF "$IP"; }
hold()    { ip route replace $IP/32 dev $DUM
            ip neigh replace proxy $IP dev $IF; }
release() { ip neigh del proxy $IP dev $IF 2>/dev/null
            ip route del $IP/32 dev $DUM 2>/dev/null; }
up()      { ip neigh del $IP dev $IF 2>/dev/null
            ping -c1 -W1 $IP >/dev/null 2>&1
            ip neigh show $IP dev $IF | grep -qE 'REACH|STALE'; }
wake()    { has && release
            kill -USR1 "$SELF"
            for n in 1 2 3; do etherwake -b -i $IF $MAC; sleep 1; done; }

# RDP SYN from VPN or LAN -> wake if the PC is not answering
for i in wg0 $IF; do
  tcpdump -i $i -n -l -q "$SYN" 2>/dev/null | while read l; do wake; done &
done

# PC woke up on its own (power button, keyboard...) -> stop impersonating it
while :; do
  has && tcpdump -i $IF -n -c1 -q "ether src $MAC" >/dev/null 2>&1 && has && release
  sleep 2
done &

# PC silent for ~12s (and not just woken) -> answer ARP in its name
f=0
while sleep 2; do
  has && continue
  [ $(( $(date +%s) - woke_at )) -lt 60 ] && { f=0; continue; }
  up && { f=0; continue; }
  f=$((f+1))
  [ $f -ge 4 ] && { hold; f=0; }
done
