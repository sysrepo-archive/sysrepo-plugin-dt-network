ifconfig eth0 | awk '/RX bytes/ { print $2 }' | cut -d':' -f2
