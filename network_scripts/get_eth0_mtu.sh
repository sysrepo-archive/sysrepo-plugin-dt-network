ifconfig eth0 | awk '/MTU:/ {print $5}' | sed 's/\MTU://g'
