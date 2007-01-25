#!/bin/sh
PID=`ps x | grep "vsftpd" | awk '{ print $1 }' | sort -r | head`
echo "Debugging $PID..."
gdb ./vsftpd.exe $PID

