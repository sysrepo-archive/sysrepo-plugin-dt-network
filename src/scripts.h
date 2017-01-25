#include <stdio.h>

#define SCRIPT "/usr/share/sysrepo/network"

const char *cmd_ifconfig = SCRIPT"/get_eth0.sh";
const char *cmd_ip = SCRIPT"/get_eth0_ip.sh";
const char *cmd_netmask = SCRIPT"/get_eth0_netmask.sh";
const char *cmd_enabled = SCRIPT"/get_eth0_enabled.sh";
const char *cmd_mtu = SCRIPT"/get_eth0_mtu.sh";
const char *cmd_forwarding = SCRIPT"/get_eth0_forwarding.sh";
const char *cmd_origin = SCRIPT"/get_eth0_origin.sh";
const char *cmd_mac = SCRIPT"/get_eth0_mac.sh";
const char *cmd_throughput = SCRIPT"/get_eth0_throughput.sh";
const char *cmd_speed = SCRIPT"/get_eth0_speed.sh";
const char *cmd_rx = SCRIPT"/get_eth0_rx.sh";
const char *cmd_tx = SCRIPT"/get_eth0_tx.sh";
const char *cmd_rx_err = SCRIPT"/get_eth0_rx_err.sh";
const char *cmd_tx_err = SCRIPT"/get_eth0_tx_err.sh";

