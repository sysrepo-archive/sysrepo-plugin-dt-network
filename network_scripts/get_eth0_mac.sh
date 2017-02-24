ifconfig ${1} | awk '/HWaddr / { print $5 }'
