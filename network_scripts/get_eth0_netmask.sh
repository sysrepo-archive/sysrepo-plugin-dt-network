ifconfig eth0 | awk '/inet / { print $4}' | cut -d':' -f2
