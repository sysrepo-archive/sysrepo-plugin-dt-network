ping6 -c 2 -W 1 -I ${1} ff02::2 | awk '/ bytes from / {print $4}'
