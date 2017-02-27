/* Author: Antonio Paunovic <antonio.paunovic@sartura.hr> */

#include <stdbool.h>
#include <libubox/list.h>
#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"
#include "sysrepo/plugins.h"

#define IP_SIZE 15

typedef char uint8;

typedef enum ip_addr_origin_s
{
    IP_ADDR_ORIGIN_OTHER,
    IP_ADDR_ORIGIN_STATIC,
    IP_ADDR_ORIGIN_DHCP,
    IP_ADDR_ORIGIN_LINK_LAYER,
    IP_ADDR_ORIGIN_RANDOM,
} ip_addr_origin;

ip_addr_origin string_to_origin(const char *str)
{
    ip_addr_origin rc = IP_ADDR_ORIGIN_OTHER;

    if (!strcmp(str, "static") || !strcmp(str, "'static'")) {
        rc = IP_ADDR_ORIGIN_STATIC;
    }

    return rc;
}

typedef enum neighbor_origin_s
{
    NEIGHBOR_ORIGIN_OTHER,
    NEIGHBOR_ORIGIN_STATIC,
    NEIGHBOR_ORIGIN_DYNAMIC,
} neighbor_origin;

struct ip_v4
{
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

    struct neighbor_v4
    {
        char *ip;
        char *link_layer_address;
    } neighbor;

    /* neighbor list */
    /* subnet list */
};

struct ip_v6
{
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

struct if_interface
{
    struct list_head head;

    struct ip_v4 *ipv4;

    struct iface_ipv6_s
    {
        bool forwarding;
        unsigned short mtu;

        struct address_ipv6            /* list */
        {
            char *ip;
            uint8 prefix_length;
            ip_addr_origin origin;
        } address;

        enum iface_status
        {
            PREFFERED,
            DEPRECATED,
            INVALID,
            INACCESSIBLE,
            UNKOWN,
            TENTATIVE,
            DUPLICATE,
            OPTIMISTIC,
        } status;

        struct if_neighbor_v6 /* list */
        {
            char *ip;
            char *link_layer_address;
            neighbor_origin origin;
            bool is_router;
        } neighbor_v6;

        enum iface_state
        {
            INCOMPLETE,
            REACHABLE,
            STALE,
            DELAY,
            PROBE,
        } state;
    } iface_ipv6;
};

struct plugin_ctx {
    struct list_head *interfaces;
    char *key;                  /* interface name */
    sr_subscription_ctx_t *subscription;
};
