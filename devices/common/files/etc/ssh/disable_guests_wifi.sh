#!/bin/sh

# Define the radio and SSID you want to monitor
RADIO="default_radio0"         # Specify the radio to control
SSID="Oded.p"          # The SSID name to search for

# Find the interface name associated with the specified SSID
INTERFACE=$(uci get wireless.default_radio0.ifname 2>/dev/null)

# Check if the interface was found
if [ -z "$INTERFACE" ]; then
    exit 1
fi

# Infinite loop with a delay of 2 minutes between checks
while true; do
    # Trust our own last UCI write instead of querying a netdev that may not
    # exist while the radio is disabled (avoids "No such device" errors).
    RADIO_DISABLED=$(uci -q get wireless."$RADIO".disabled)
    if [ "$RADIO_DISABLED" = "1" ]; then
        RADIO_STATUS=1  # Radio is disabled
    else
        RADIO_STATUS=0  # Radio is enabled
    fi

    if [ "$RADIO_STATUS" -eq 0 ]; then
        # Only query the interface when it actually exists
        STA_COUNT=$(iw dev "$INTERFACE" station dump 2>/dev/null | grep -c Station)
    else
        STA_COUNT=0
    fi

    if [ "$STA_COUNT" -eq 0 ]; then
        # No stations connected
        if [ "$RADIO_STATUS" -eq 0 ]; then
            # Disable the radio if it's currently enabled
            uci set wireless."$RADIO".disabled=1
            uci commit wireless
            wifi reload
        fi
    else
        # Stations are connected
        if [ "$RADIO_STATUS" -eq 1 ]; then
            # Enable the radio if it's currently disabled
            uci set wireless."$RADIO".disabled=0
            uci commit wireless
            wifi reload
        fi
    fi

    # Wait for 5 minutes before the next check
    sleep 300
done
