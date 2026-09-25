#!/bin/sh
RADIO="default_radio0"

DEBUG="${DEBUG:-0}"
# Never pass a raw logread line to dbg(), and never log unconditionally
# on every line seen: this script reads its own logger output back
# through the same logread loop, so an unfiltered/echoed debug line
# would re-match the case below (or amplify itself) forever. Only log
# at decisive branch points.
dbg() { [ "$DEBUG" = "1" ] && logger -t disable_guests_wifi "$*"; }

INTERFACE=$(uci get wireless.default_radio0.ifname 2>/dev/null)
if [ -z "$INTERFACE" ]; then
    dbg "no interface configured for $RADIO, exiting"
    exit 1
fi
dbg "start: RADIO=$RADIO INTERFACE=$INTERFACE"

disable_radio() {
    RADIO_DISABLED=$(uci -q get wireless."$RADIO".disabled)
    if [ "$RADIO_DISABLED" = "1" ]; then
        dbg "disable_radio(): already disabled, skipping"
        return
    fi
    dbg "disable_radio(): disabling $RADIO"
    uci set wireless."$RADIO".disabled=1
    uci commit wireless
    wifi reload
    dbg "disable_radio(): $RADIO disabled"
}

cleanup() {
    dbg "stopping: killing process group"
    kill -TERM 0 2>/dev/null
    exit 0
}
trap cleanup TERM INT

dbg "listening for hostapd events via logread"
logread -f | while read -r line; do
    case "$line" in
        *"Open-WIFI: AP-ENABLED"*)
            dbg "AP-ENABLED, waiting up to 120s for a connection"
            # No one connected within 2 minutes of turning it on -> back off.
            deadline=$(( $(date +%s) + 120 ))
            got_connection=0
            while :; do
                remaining=$(( deadline - $(date +%s) ))
                if [ "$remaining" -le 0 ]; then
                    dbg "120s elapsed with no connection"
                    break
                fi
                if read -t "$remaining" -r inner; then
                    case "$inner" in
                        *"Open-WIFI: AP-STA-CONNECTED"*) got_connection=1; dbg "connection detected, cancelling timeout"; break ;;
                        *"Open-WIFI: AP-DISABLED"*) dbg "AP disabled manually, cancelling timeout"; break ;;
                    esac
                else
                    dbg "120s elapsed with no connection"
                    break
                fi
            done
            [ "$got_connection" = 0 ] && disable_radio
            ;;
        *"Open-WIFI: AP-STA-DISCONNECTED"*)
            dbg "AP-STA-DISCONNECTED event"
            RADIO_DISABLED=$(uci -q get wireless."$RADIO".disabled)
            if [ "$RADIO_DISABLED" = "1" ]; then
                dbg "already disabled, ignoring"
                continue
            fi
            # let the kernel's station table settle before trusting it
            read -t 1 _
            STA_COUNT=$(iw dev "$INTERFACE" station dump 2>/dev/null | grep -c Station)
            dbg "STA_COUNT=$STA_COUNT"
            [ "$STA_COUNT" -eq 0 ] && disable_radio
            ;;
    esac
done
