#!/bin/sh

# Function to log messages
log() {
    timestamp=$(date +"%Y-%m-%d %T")
    logger -t run_scripts "[$timestamp] $1"
}
sleep 15
# Script 1
#script1="/etc/ssh/wan_wifi-Notify.sh"
if [ -f "$script1" ]; then
    log "Running script 1 in the background..."
    sh "$script1" &
else
    log "Script 1 not found: $script1"
fi

# Script 2
script2="/etc/ssh/wakeuppc.sh"
if [ -f "$script2" ]; then
    log "Running script 2 in the background..."
    "$script2" &
else
    log "Script 2 not found: $script2"
fi

# Script 3
script3="/etc/ssh/multicast-relay.py"
if [ -f "$script3" ]; then
    log "Running script 3 in the background..."
python3 "$script3" --interfaces br-smarthome br-open br-lan --homebrewNetifaces --ttl 255 &

else
    log "Script 3 not found: $script3"
fi

sleep 2

# Script 4
#script4="/etc/ssh/connection-status-watcher.sh"
if [ -f "$script4" ]; then
    log "Running script 4 in the background..."
    sh "$script4" &
else
    log "Script 4 not found: $script4"
fi

# Script 5
script5="/etc/ssh/disable_guests_wifi.sh"
if [ -f "$script5" ]; then
    log "Running script 5 in the background..."
    sh "$script5" &
else
    log "Script 5 not found: $script5"
fi


# Add more scripts here if needed

log "All scripts started."
exit 0
