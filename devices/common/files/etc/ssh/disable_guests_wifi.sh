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
    # Check for associated stations on the specified interface
    STA_COUNT=$(iw dev "$INTERFACE" station dump | grep -c Station)

    # Check if the radio is enabled by querying iw command directly
    RADIO_ENABLED=$(iw dev "$INTERFACE" info | grep 'type AP' | wc -l)

    # Determine RADIO_STATUS based on the iw output
    if [ "$RADIO_ENABLED" -gt 0 ]; then
        RADIO_STATUS=0  # Radio is enabled
    else
        RADIO_STATUS=1  # Radio is disabled
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
