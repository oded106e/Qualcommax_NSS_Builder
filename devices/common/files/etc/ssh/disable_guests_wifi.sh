#!/bin/sh
RADIO="default_radio0"
INTERFACE=$(uci get wireless.default_radio0.ifname 2>/dev/null)
[ -z "$INTERFACE" ] && exit 1

logread -f | while read -r line; do
    case "$line" in
        *"Open-WIFI: AP-STA-DISCONNECTED"*) ;;
        *) continue ;;
    esac

    RADIO_DISABLED=$(uci -q get wireless."$RADIO".disabled)
    [ "$RADIO_DISABLED" = "1" ] && continue

    # let the kernel's station table settle before trusting it
    read -t 1 _

    STA_COUNT=$(iw dev "$INTERFACE" station dump 2>/dev/null | grep -c Station)
    if [ "$STA_COUNT" -eq 0 ]; then
        uci set wireless."$RADIO".disabled=1
        uci commit wireless
        wifi reload
    fi
done
