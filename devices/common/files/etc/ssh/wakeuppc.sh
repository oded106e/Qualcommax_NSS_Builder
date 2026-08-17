#!/bin/sh

# ================== CONFIG ==================
TARGET_MAC="7C:66:EF:F0:C4:3C"
DELAY=300 
VERBOSE_LOG=0
LAST_WOL_FILE="/tmp/last_wol_sent_time"

# ================== LOGGING ==================
vlogger() {
  [ "$VERBOSE_LOG" -eq 1 ] && logger -t wol-script "[VERBOSE] $1"
}

# ================== FUNCTIONS ==================

send_wol_packet() {
  # ????? ???? ?????? ????? ?????? ????? ???????
  local cmd_path=$(which etherwake)
  vlogger "Debug: etherwake path is [$cmd_path]"
  
  local exec_cmd="$cmd_path -i br-lan $TARGET_MAC"
  logger -t wol-script "EXECUTION: Sending WOL signal via command: $exec_cmd"
  
  # ???? ?????? ??? ???????
  local output=$($cmd_path -i br-lan "$TARGET_MAC" 2>&1)
  local exit_code=$?
  
  if [ $exit_code -eq 0 ]; then
    logger -t wol-script "SUCCESS: Packet sent to $TARGET_MAC (Exit code: $exit_code)"
  else
    logger -t wol-script "FAILURE: etherwake failed with exit code $exit_code. Output: $output"
  fi

  date +%s > "$LAST_WOL_FILE"
  vlogger "Timestamp updated in $LAST_WOL_FILE"
}

should_send_wol() {
  if [ -f "$LAST_WOL_FILE" ]; then
    local last_sent=$(cat "$LAST_WOL_FILE")
    local current_time=$(date +%s)
    local elapsed=$((current_time - last_sent))

    vlogger "TIME CHECK: Current=$current_time, Last=$last_sent, Elapsed=$elapsed, Delay=$DELAY"

    if [ "$elapsed" -ge "$DELAY" ]; then
      vlogger "CONDITION MET: Delay satisfied ($elapsed >= $DELAY)."
      return 0
    else
      vlogger "CONDITION FAILED: WOL suppressed. Only $elapsed seconds passed of $DELAY."
      return 1
    fi
  else
    vlogger "CONDITION MET: No previous WOL record file found."
    return 0
  fi
}

check_and_send_wol() {
  vlogger "Traffic detected. Evaluating WOL conditions..."
  if should_send_wol; then
    send_wol_packet
  else
    vlogger "WOL skipped due to delay logic."
  fi
}

# ================== TRAFFIC MONITORING ==================

# Monitor WireGuard RDP traffic
tcpdump -i wg0 -n -l port 3389 2>/dev/null | \
while read line
do
  logger -t wol-script "TRIGGER [WG]: Raw traffic match: $line"
  check_and_send_wol
done &

logger -t wol-script "WOL script is running. Debugging enabled."
