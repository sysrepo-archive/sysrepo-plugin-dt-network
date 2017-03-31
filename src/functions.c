#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "functions.h"

#define ADDR_STR_BUF_SIZE 80


char *
get_ip4(struct function_ctx *ctx, struct rtnl_link *link);

static int
socket_init(struct nl_sock **socket, int protocol)
{
    int error = 0;

    *socket = nl_socket_alloc();
    if (socket == NULL) {
        fprintf(stderr, "unable to allocate netlink socket for route family.");
    }

    error = nl_connect(*socket, protocol);
    if (error < 0) {
        fprintf(stderr, "unable to connect to route socket (%s)", nl_geterror(error));
        goto error;
    }

    return 0;
  error:
    nl_socket_free(*socket);

    return error;
}

struct function_ctx *
make_function_ctx()
{
    /* struct nl_cache *link_cache, *addr_cache; */
    struct function_ctx *hctx;
    int rc = 0;

    hctx = calloc(1, sizeof(*hctx));


    struct nl_sock *sk;
    rc = socket_init(&sk, NETLINK_ROUTE);
    if (rc) {
        fprintf(stderr, "socket not initialized\n");
        goto error;
    }
    hctx->socket = sk;

    rc = rtnl_link_alloc_cache(hctx->socket, AF_UNSPEC, &(hctx->cache_link));
    if (rc) {
        fprintf(stderr, "cache alloc error: %d\n", rc);
        goto error;
    }

    rc = rtnl_addr_alloc_cache(hctx->socket, &(hctx->cache_addr));
    if (rc != 0) {
        printf("cant allocate addr cache: %d\n", rc);
        goto error;
    }

    return hctx;
  error:
    free(hctx);
    return NULL;
}

void
free_function_ctx(struct function_ctx *ctx)
{
    /* Maybe some libnl freeing before ctx ? */
    free(ctx);
}

void
get_prefixlen_cb(struct nl_object *nlobj, void *data)
{
    uint8_t *res = data;
    uint8_t prefixlen = (uint8_t) rtnl_addr_get_prefixlen((struct rtnl_addr *) nlobj);
    *res = prefixlen;
}


uint8_t
get_prefixlen(struct function_ctx *ctx)
{
    uint8_t prefixlen;
    nl_cache_foreach(ctx->cache_addr, get_prefixlen_cb, (void*) &prefixlen);
    return prefixlen;
}

void
get_ip4_cb(struct nl_object *nlobj, void *data)
{
    struct {
        int ifindex;
        char result_addr[80];
    } *msg = data;

    int ifindex = msg->ifindex;
    struct rtnl_addr *addr = (struct rtnl_addr *) nlobj;
    int ifindex_cur;
    int family;
    struct nl_addr *addr_local;

    ifindex_cur = rtnl_addr_get_ifindex(addr);
    if (ifindex != ifindex_cur) {
        return;
    }

    family = rtnl_addr_get_family(addr);
    if (AF_INET6 == family) {
        return;
    }

    addr_local = rtnl_addr_get_local(addr);
    nl_addr2str(addr_local, msg->result_addr, sizeof(msg->result_addr));
}

char *
get_ip4(struct function_ctx *ctx, struct rtnl_link *link)
{
    struct nl_cache *addr_cache;

    int ifindex = rtnl_link_get_ifindex(link);

    printf("interface with index %d\n", ifindex);

    struct {
        int ifindex;
        char result_addr[80];
    } *msg;

    rtnl_addr_alloc_cache(ctx->socket, &addr_cache);
    msg = calloc(1, sizeof(*msg));
    msg->ifindex = ifindex;

    printf("cache_addr %d\n", ctx->cache_addr);
    nl_cache_foreach(ctx->cache_addr, get_ip4_cb, (void*)msg);

    char *res = strdup(msg->result_addr);

    free(msg);

    return res;
}

char *
get_mac(struct rtnl_link *link)
{
    char buf[SIZE_BUF];
    struct nl_addr *addr = rtnl_link_get_addr(link);
    if (!addr) {
        fprintf(stderr, "addr error\n");
    }

    nl_addr2str(addr, buf, sizeof(buf));
    return strdup(buf);
}

int
parse_tc_info(char buf[SIZE_BUF], uint64_t stat,
              struct tc_info_entry *tc_info, const int count)
{
    char *pref;

    for (int i = 0; i < count; i++) {
        pref = tc_info[i].name;

        if (!strncmp(pref, buf, strlen(pref))) {
            tc_info[i].val = stat;
            return 0;
        }
    }

    return -1;
}

void
print_tc_info(struct tc_info_entry *tc_info, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        printf("%s %" PRIu64 "\n", tc_info[i].name, tc_info[i].val);
    }
}

void
get_tc_info(struct rtnl_link *link)
{
    int count;
    uint64_t stat;
    char buf[SIZE_BUF] = { 0 };
    struct tc_info_entry entries[] =  {
        { "rx_packets", 0 },
        { "rx_bytes",   0 },
        { "rx_errors",  0 },
        { "tx_packets", 0 },
        { "tx_bytes",   0 },
        { "tx_errors",  0 },
    };

    count = sizeof(entries) / sizeof(entries[0]);
    /* int family = rtnl_link_get_family(link); */
    /* struct nl_addr *addr = rtnl_link_get_addr(link); */

    for (int i = 0; i < RTNL_LINK_STATS_MAX; i++) {
        stat = rtnl_link_get_stat(link, i);
        rtnl_link_stat2str(i, buf, sizeof(buf));
        parse_tc_info(buf, stat, entries, count);
    }
}

void
set_ip(char *ipv4)
{
}

int
set_mtu(struct rtnl_link *link, uint16_t mtu)
{
    if (mtu < MIN_MTU|| mtu > MAX_MTU) {
        fprintf(stderr, "MTU of value %uh is invalid, valid values are from %d to %d.", mtu, MIN_MTU, MAX_MTU);
        return -1;
    }

    rtnl_link_set_mtu(link, mtu);

    return 0;
}

uint16_t
get_mtu(struct rtnl_link *link)
{
    unsigned int mtu = rtnl_link_get_mtu(link);

    return mtu;
}

uint32_t
get_forwarding(struct rtnl_link *link)
{
    uint32_t value;
    const int IPV4_DEVCONF_FORWARDING = 1;

    rtnl_link_inet_get_conf(link, IPV4_DEVCONF_FORWARDING, &value);

    return value;
}

void
set_operstate(struct rtnl_link *link, uint8_t operstate)
{
    rtnl_link_set_operstate(link, operstate);
}

char *
get_operstate(struct rtnl_link *link)
{
    uint8_t operstate_code;
    char buf[64] = { 0 };

    int flag = rtnl_link_get_flags(link);
    rtnl_link_flags2str(flag, buf, sizeof(buf));

    operstate_code = rtnl_link_get_operstate(link);
    rtnl_link_operstate2str(operstate_code, buf, sizeof(buf));

    return strdup(buf);
}

/* Callback used for applying changes to cache. */
/* static void */
/* set_cb(struct nl_object *obj, void *arg) */
/* { */
/*     struct rtnl_link *link = nl_object_priv(obj); */
/*     struct rtnl_link *change = arg; */
/*     struct nl_dump_params params = { */
/*         .dp_type = NL_DUMP_LINE, */
/*         .dp_fd = stdout, */
/*     }; */
/*     int err; */

/*     if ((err = rtnl_link_change(sk, link, change, 0)) < 0) */
/*         fprintf(stderr, "Unable to change link: %s", */
/*                 nl_geterror(err)); */

/*     printf("Changed "); */
/*     nl_object_dump(OBJ_CAST(link), &params); */
/* } */



int
functions_init()
{
    int rc = SRPLUG_OK;
    /* char *if_name = "enp3s0"; */
    /* link = rtnl_link_get_by_name(link_cache, if_name); */
    /* uint16_t mtu = get_mtu(link); */
    /* printf("mtu: %hu\n", mtu); */

    /* rc = set_mtu(link, 1300u); */
    /* printf("mtu: %hu\n", get_mtu(link)); */

    /* char *operstate = get_operstate(link); */
    /* printf("operstate: %s\n", operstate); */

    /* get_tc_info(link); */

    /* char buf[SIZE_BUF]; */

    /* /\* struct cache_context *nctx; *\/ */
    /* /\* nctx = calloc(1, sizeof(*nctx)); *\/ */
    /* /\* nl_cache_init(sk, nctx); *\/ */
    /* /\* nl_get_ipv4(nctx, buf); *\/ */

    /* char *mac = get_mac(link); */
    /* printf("mac: %s\n", mac); */

    /* char *ipv4 = get_ip4(link); */


    /* What to do? */
    /* rtnl_link_set_name(change, if_name); */
    /* rtnl_link_set_mtu(change, 666u); */

    /* nl_cache_foreach_filter(link_cache, OBJ_CAST(link), set_cb, change); */

    /* nl_socket_free(sk); */

    return rc;
}

int
main(int argc, char *argv[])
{
    fprintf(stderr, "main started\n");
    struct nl_cache *link_cache, *addr_cache;
    struct function_ctx *ctx;
    int rc = 0;
    ctx = make_function_ctx();
    if (rc) {
        fprintf(stderr, "make function context fail %d (ctx==NULL %d)\n", rc, ctx==NULL);
    }
    link_cache = ctx->cache_link;
    addr_cache = ctx->cache_addr;
    struct rtnl_link *link = rtnl_link_get_by_name(link_cache, "enp3s0");
    int ifindex = rtnl_link_get_ifindex(link);

    const char *ip = get_ip4(ctx, link);
    free(ctx);

}
