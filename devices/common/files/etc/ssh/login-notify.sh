#!/bin/sh

# Check if the session type is not "close_session"
if [ "$PAM_TYPE" != "close_session" ]; then
    # Check if the remote host is 192.168.0.201, if so, exit the script
    if [ "$PAM_RHOST" = "192.168.0.201" ]; then
        exit 0
    fi
    
    # Construct the subject of the email
    subject="SSH Login: $PAM_USER from $PAM_RHOST on OpenWRT"
    
    # Capture the environment variables as the message
    message="`env`"
    
    # Send the email
    echo "$message" | mailx -s "$subject" "oded106e@gmail.com"
fi
