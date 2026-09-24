#!/bin/sh
RADIO="default_radio0"
INTERFACE=$(uci get wireless.default_radio0.ifname 2>/dev/null)
[ -z "$INTERFACE" ] && exit 1

disable_radio() {
    RADIO_DISABLED=$(uci -q get wireless."$RADIO".disabled)
    [ "$RADIO_DISABLED" = "1" ] && return
    uci set wireless."$RADIO".disabled=1
    uci commit wireless
    wifi reload
}

logread -f | while read -r line; do
    case "$line" in
        *"Open-WIFI: AP-ENABLED"*)
            # No one connected within 2 minutes of turning it on -> back off.
            deadline=$(( $(date +%s) + 120 ))
            got_connection=0
            while :; do
                remaining=$(( deadline - $(date +%s) ))
                [ "$remaining" -le 0 ] && break
                if read -t "$remaining" -r inner; then
                    case "$inner" in
                        *"Open-WIFI: AP-STA-CONNECTED"*) got_connection=1; break ;;
                        *"Open-WIFI: AP-DISABLED"*) break ;;
                    esac
                else
                    break
                fi
            done
            [ "$got_connection" = 0 ] && disable_radio
            ;;
        *"Open-WIFI: AP-STA-DISCONNECTED"*)
            RADIO_DISABLED=$(uci -q get wireless."$RADIO".disabled)
            [ "$RADIO_DISABLED" = "1" ] && continue
            # let the kernel's station table settle before trusting it
            read -t 1 _
            STA_COUNT=$(iw dev "$INTERFACE" station dump 2>/dev/null | grep -c Station)
            [ "$STA_COUNT" -eq 0 ] && disable_radio
            ;;
    esac
done
