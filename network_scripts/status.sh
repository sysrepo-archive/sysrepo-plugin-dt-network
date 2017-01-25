ip -6 a show ${1} | awk '/inet6 '${2}'/ {print $5}'
