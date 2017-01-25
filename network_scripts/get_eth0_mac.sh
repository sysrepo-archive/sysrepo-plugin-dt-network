ifconfig eth0 | awk '/HWaddr / { print $5 }'
