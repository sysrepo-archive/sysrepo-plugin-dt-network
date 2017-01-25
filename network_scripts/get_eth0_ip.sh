 ifconfig eth0 | awk '/inet / { print $2}' | cut -d':' -f2
