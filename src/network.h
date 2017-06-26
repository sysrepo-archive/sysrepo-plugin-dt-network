/* Author: Antonio Paunovic <antonio.paunovic@sartura.hr> */

#include <stdbool.h>
#include <libubox/list.h>

#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"
#include "sysrepo/plugins.h"

#include "functions.h"

#define IP_SIZE 15
#define XPATH_MAX_LEN 100
#define BUFSIZE 256
#define MAX_INTERFACES 10
#define MAX_INTERFACE_NAME 10
#define MAX_INTERFACE_TYPE 10
#define MAX_INTERFACE_DESCRIPTION 200
#define MAX_ADDR_LEN 32
#define RESTART_TIME_TO_WAIT 3


typedef char uint8;

typedef enum ip_addr_origin_s
{
    IP_ADDR_ORIGIN_OTHER,
    IP_ADDR_ORIGIN_STATIC,
    IP_ADDR_ORIGIN_DHCP,
    IP_ADDR_ORIGIN_LINK_LAYER,
    IP_ADDR_ORIGIN_RANDOM,
} ip_addr_origin;

ip_addr_origin
string_to_origin(const char *str)
{
    ip_addr_origin rc = IP_ADDR_ORIGIN_OTHER;

    if (!strcmp(str, "other") || !strcmp(str, "'other'")) {
        rc = IP_ADDR_ORIGIN_OTHER;
    }

    if (!strcmp(str, "static") || !strcmp(str, "'static'")) {
        rc = IP_ADDR_ORIGIN_STATIC;
    }

    if (!strcmp(str, "dhcp") || !strcmp(str, "'dhcp'")) {
        rc = IP_ADDR_ORIGIN_DHCP;
    }

    if (!strcmp(str, "link_layer") || !strcmp(str, "'link_layer'")) {
        rc = IP_ADDR_ORIGIN_LINK_LAYER;
    }

    if (!strcmp(str, "random") || !strcmp(str, "'random'")) {
        rc = IP_ADDR_ORIGIN_RANDOM;
    }

    return rc;
}

char *
origin_to_string(ip_addr_origin origin)
{
    switch(origin) {
    case IP_ADDR_ORIGIN_OTHER: return "other";
    case IP_ADDR_ORIGIN_STATIC: return "static";
    case IP_ADDR_ORIGIN_DHCP: return "dhcp";
    case IP_ADDR_ORIGIN_LINK_LAYER: return "link-layer";
    case IP_ADDR_ORIGIN_RANDOM: return "random";
    };

    /* Should not be reachable. */
    return NULL;
}

typedef enum neighbor_origin_s {
    NEIGHBOR_ORIGIN_OTHER,
    NEIGHBOR_ORIGIN_STATIC,
    NEIGHBOR_ORIGIN_DYNAMIC,
} neighbor_origin;


struct neighbor_v4 {
    char *ip;
    char *link_layer_address;
};


struct ip_v4 {
    struct list_head neighbors;
    bool enabled;
    bool forwarding;
    ip_addr_origin origin;
    unsigned short mtu;

    struct address_v4
    {
        char ip[IP_SIZE+1];
        union subnet_s
        {
            uint8 prefix_length;
            char *netmask;
        } subnet;
    } address;

    /* neighbor list */
    /* subnet list */
};

struct ip_v6 {
    bool enabled;
    bool forwarding;
    unsigned short mtu;

    struct address_v6
    {
        char *ip;
        uint8 prefix_length;
    } address;

    struct neighbor_v6
    {
        char *ip;
        char *link_layer_address;
    } neighbor;

    unsigned int dup_addr_detect_transmits;

    struct autoconf_v6
    {
        bool create_global_addresses;
        bool create_temporary_addresses;
        unsigned int temporary_valid_lifetime;
        unsigned int temporary_preffered_lifetime;
    } autoconf;
};

struct if_interface {
    struct list_head head;

    union proto {
        struct ip_v4 *ipv4;
        struct ip_v6 *ipv6;
    } proto;

    char *name;                 /* eth0, enp3s0, etc. */
    char *type;                 /* wan, lan, etc. */
    char *description;
};

struct plugin_ctx {
    struct list_head *interfaces;
    char *key;                  /* interface name */
    sr_subscription_ctx_t *subscription;
    struct function_ctx *fctx;  /* context for using libnl functions */
    struct uci_context *uctx;       /* initialization TODO ? */
};
