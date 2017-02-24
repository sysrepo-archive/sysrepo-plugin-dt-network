ifconfig ${1} | awk '/MTU:/ {print $5}' | sed 's/\MTU://g'
