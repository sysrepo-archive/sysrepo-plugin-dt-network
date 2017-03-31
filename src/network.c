/* Author: Antonio Paunovic <antonio.paunovic@sartura.hr> */

#include <stdio.h>
#include <syslog.h>

#include "network.h"
#include "scripts.h"
#include "functions.h"

#define MODULE "/ietf-ip"
#define XPATH_MAX_LEN 100
#define BUFSIZE 256
#define MAX_INTERFACES 10
#define MAX_INTERFACE_NAME 10


static struct if_interface *
make_interface_ipv4(char *name)
{
    struct if_interface *interface;
    interface = calloc(1, sizeof(*interface));
    interface->name = calloc(1, MAX_INTERFACE_NAME);
    if (!(strcpy(interface->name, name))) {
        fprintf(stderr, "make_interface_ipv4\n");
        goto error;
    }

    interface->proto.ipv4 = calloc(1, sizeof(struct ip_v4));

    return interface;

  error:
    free(interface);
    return NULL;
}

static int
ls_interfaces_cb(struct nl_msg *msg, void *arg)
{
    struct list_head *interfaces = (struct list_head *) arg;
    struct if_interface *iff;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct ifinfomsg *iface = NLMSG_DATA(nlh);
    struct rtattr *hdr = IFLA_RTA(iface);
    int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

    while (RTA_OK(hdr, remaining)) {

        if (hdr->rta_type == IFLA_IFNAME) {
            iff = make_interface_ipv4((char *) RTA_DATA(hdr));
            list_add(&iff->head, interfaces);
            printf("Found network interface %d: %s\n", iface->ifi_index, iff->name);
        }

        hdr = RTA_NEXT(hdr, remaining);
    }

    return NL_OK;
}

/* Initialize list of interfaces for given context (with ipv4 kind of interfaces). */
static void
ls_interfaces(struct plugin_ctx *ctx)
{
    struct nl_sock *socket = nl_socket_alloc();  // Allocate new netlink socket in memory.
    nl_connect(socket, NETLINK_ROUTE);  // Create file descriptor and bind socket.

    /* Send request for all network interfaces. */
    struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
    nl_send_simple(socket, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));

    /* Retrieve the kernel's answer. */
    nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, ls_interfaces_cb, ctx->interfaces);
    nl_recvmsgs_default(socket);
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name,
                 sr_notif_event_t event, void *private_ctx)
{
    return SR_ERR_OK;
}

static int
str_from_cmd(const char *cmd, const char *cmd_arg, const char *fmt, char *ptr)
{
    int rc = 0;
    FILE *fp;
    char buf[BUFSIZE];
    char cmd_buf[BUFSIZE];
    char *cmd_fmt = "%s %s";

    sprintf(cmd_buf, cmd_fmt, cmd, cmd_arg);

    if ((fp = popen(cmd_buf, "r")) == NULL) {
        fprintf(stderr, "Error opening pipe!\n");
        return -1;
    }

    if (fgets(buf, BUFSIZE, fp) != NULL) {
        sscanf(buf, fmt, ptr);
    } else {
        fprintf(stderr, "Error running %s command.\n", cmd);
    }

    rc= pclose(fp);

    return rc;
}

static int
int_from_cmd(const char *cmd, const char *cmd_arg, const char *fmt, void *ptr)
{
    int rc = 0;
    FILE *fp;
    char buf[BUFSIZE];

    char cmd_buf[BUFSIZE];
    char *cmd_fmt = "%s %s";

    sprintf(cmd_buf, cmd_fmt, cmd, cmd_arg);

    if ((fp = popen(cmd, "r")) == NULL) {
        fprintf(stderr, "Error opening pipe!\n");
        return -1;
    }

    if (fgets(buf, BUFSIZE, fp) != NULL) {
        sscanf(buf, fmt, ptr);
    } else {
        fprintf(stderr, "Error running %s command.\n", cmd);
    }

    rc = pclose(fp);

    return rc;
}

static int
sysrepo_commit_network(sr_session_ctx_t *sess, struct plugin_ctx *ctx)
{
    char xpath[XPATH_MAX_LEN];
    const char *xpath_fmt = "/ietf-interfaces:interfaces/interface[name='%s']/%s";
    const char *xpath_fmt_ipv4 = "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/%s";
    int rc = SR_ERR_OK;
    sr_val_t val = { 0 };
    sr_val_t *v = NULL;

    struct if_interface *iface;
    list_for_each_entry(iface, ctx->interfaces, head) {

        /* Set forwarding. */
        val.type = SR_BOOL_T;
        val.data.bool_val = true;
        sprintf(xpath, xpath_fmt_ipv4, iface->name, "forwarding");
        rc = sr_set_item(sess, xpath,
                         &val, SR_EDIT_DEFAULT);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error by sr_set_item: %s\n", sr_strerror(rc));
            goto cleanup;
        }

        rc = sr_new_values(1, &v);
        sprintf(xpath, xpath_fmt, iface->name, "type");
        sr_val_set_xpath(&v[0], xpath);
        sr_val_set_str_data(&v[0], SR_IDENTITYREF_T, "ethernetCsmacd");
        v[0].type = SR_IDENTITYREF_T;
        /* val.data.identityref_val = "ethernetCsmacd"; */
        rc = sr_set_item(sess, xpath,
                         &v[0], SR_EDIT_DEFAULT);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error by sr_set_item: %s\n", sr_strerror(rc));
            goto cleanup;
        }

        /* set MTU. */
        val.type = SR_UINT16_T;
        val.data.uint16_val = iface->proto.ipv4->mtu;
        printf(xpath, xpath_fmt_ipv4, iface->name, "mtu");
        rc = sr_set_item(sess, xpath, &val, SR_EDIT_DEFAULT);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error by sr_set_item: %s\n", sr_strerror(rc));
            goto cleanup;
        }

        /* Commit values set. */
        rc = sr_commit(sess);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error by sr_commit: %s\n", sr_strerror(rc));
            goto cleanup;
        }
    }

    return SR_ERR_OK;

  cleanup:
    return rc;
}

static int
init_config_ipv4(struct ip_v4 *ipv4)
{
    char *interface_name = "eth0";
    struct function_ctx *fun_ctx;
    char buf[BUFSIZE];

    fun_ctx = make_function_ctx();

    printf("acache %d\n", fun_ctx->cache_link);
    struct rtnl_link *link = rtnl_link_get_by_name(fun_ctx->cache_link, interface_name);
    if (link == NULL) {
        fprintf(stderr, "failed to get link\n");
        goto error;
    }

    // IP
    strcpy(ipv4->address.ip, get_ip4(fun_ctx, link));

    // MTU
    ipv4->mtu = get_mtu(link);

    // ENABLED (operstate?)
    ipv4->enabled = !strcmp(get_operstate(link), "UP") ? true : false;

    // PREFIX LENGTH
    ipv4->address.subnet.prefix_length = get_prefixlen(fun_ctx);

    // FORWARDING
    ipv4->forwarding = get_forwarding(link);

    // ORIGIN (uci)
    str_from_cmd(cmd_origin, interface_name, "%s", buf);
    ipv4->origin = string_to_origin(buf);

    free_function_ctx(fun_ctx);

    return 0;

  error:
    return -1;
}

static int
init_config(struct plugin_ctx *ctx)
{
    struct if_interface *iface;
    list_for_each_entry(iface, ctx->interfaces, head) {
        if (iface->proto.ipv4 && !strcmp(iface->name, "eth0")) {
            fprintf(stderr, "init config %s\n", iface->name);
            init_config_ipv4(iface->proto.ipv4);
        }
    }

    fprintf(stderr, "exit init config\n");
    return 0;
}

/* Handle operational data. */
static int
data_provider_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    char xpath[XPATH_MAX_LEN];
    const char *xpath_fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/%s";
    sr_val_t *v = NULL;
    sr_xpath_ctx_t xp_ctx = {0};
    int i_v = 0;
    int rc = SR_ERR_OK;

    printf("Data for '%s' requested.\n", xpath);

    struct plugin_ctx *ctx = (struct plugin_ctx *) private_ctx;
    char *interface_name = ctx->key; /* PLACEHOLDER */

    struct if_interface *iface;
    list_for_each_entry(iface, ctx->interfaces, head) {
        const char *if_name = iface->name;

        if (sr_xpath_node_name_eq(xpath, "interface")) {

            *values_cnt = 4;

            /* allocate space for data to return */
            rc = sr_new_values(*values_cnt, &v);
            if (SR_ERR_OK != rc) {
                return rc;
            }

            sprintf(xpath, xpath_fmt, if_name, "type");
            sr_val_set_xpath(&v[i_v], xpath);
            sr_val_set_str_data(&v[i_v], SR_IDENTITYREF_T, "ethernetCsmacd");
            i_v++;

            printf("i_v %d\n", i_v);
            /* oper-status */
            char buf[BUFSIZE] = { 0 };
            str_from_cmd(cmd_enabled, interface_name, "%s", buf);
            printf("buf %s\n", buf);

            sprintf(xpath, xpath_fmt, if_name, "oper-status");
            sr_val_set_xpath(&v[i_v], xpath);
            sr_val_set_str_data(&v[i_v], SR_ENUM_T, buf);
            i_v++;

            printf("i_v %d\n", i_v);

            /* phys address */
            str_from_cmd(cmd_mac, interface_name, "%s", buf);
            printf("mac %s\n", buf);

            sprintf(xpath, xpath_fmt, if_name, "phys-address");
            sr_val_set_xpath(&v[i_v], xpath);
            sr_val_set_str_data(&v[i_v], SR_STRING_T, buf);
            i_v++;

            printf("i_v %d\n", i_v);
            /* speed */
            uint64_t speed = 0;
            int_from_cmd(cmd_speed, interface_name, "%lu", &speed);
            printf("speed %llu\n", speed);
            sprintf(xpath, xpath_fmt, if_name, "speed");
            sr_val_set_xpath(&v[i_v], xpath);
            v[i_v].type = SR_UINT64_T;
            v[i_v].data.uint64_val = speed;
            i_v++;

            printf("i_v %d\n", i_v);
            /* statistics */
            *values = v;

        } else if (sr_xpath_node_name_eq(xpath, "statistics")) {

            *values_cnt = 4;

            rc = sr_new_values(*values_cnt, &v);
            if (SR_ERR_OK != rc) {
                return rc;
            }

            uint64_t tx = 0;
            int_from_cmd(cmd_tx, interface_name, "%lu", &tx);
            sprintf(xpath, xpath_fmt, if_name, "statistics/out-octets");
            sr_val_set_xpath(&v[i_v], xpath);
            v[i_v].type = SR_UINT64_T;
            v[i_v].data.uint64_val = tx;
            i_v++;

            uint32_t tx_err = 0;
            int_from_cmd(cmd_tx_err, interface_name, "%lu", &tx_err);
            sprintf(xpath, xpath_fmt, if_name, "statistics/out-errors");
            sr_val_set_xpath(&v[i_v], xpath);
            v[i_v].type = SR_UINT32_T;
            v[i_v].data.uint32_val = tx_err;
            i_v++;

            uint64_t rx = 0;
            int_from_cmd(cmd_rx, interface_name, "%lu", &rx);
            sprintf(xpath, xpath_fmt, if_name, "statistics/in-octets");
            sr_val_set_xpath(&v[i_v], xpath);
            v[i_v].type = SR_UINT64_T;
            v[i_v].data.uint64_val = rx;
            i_v++;

            uint32_t rx_err = 0;
            int_from_cmd(cmd_rx_err, interface_name, "%lu", &rx_err);
            sprintf(xpath, xpath_fmt, if_name, "statistics/in-errors");
            sr_val_set_xpath(&v[i_v], xpath);
            v[i_v].type = SR_UINT32_T;
            v[i_v].data.uint32_val = rx_err;
            i_v++;

            *values = v;

        } else if (sr_xpath_node_name_eq(xpath, "ipv4")) {

            *values_cnt = 1;

            rc = sr_new_values(*values_cnt, &v);
            if (SR_ERR_OK != rc) {
                return rc;
            }

            uint16_t mtu = 0;
            int_from_cmd(cmd_mtu, interface_name, "%lu", &mtu);
            mtu = (uint16_t) mtu;
            sprintf(xpath, xpath_fmt, if_name, "statistics/ipv4/mtu");
            sr_val_set_xpath(&v[i_v], xpath);
            v[i_v].type = SR_UINT16_T;
            v[i_v].data.uint16_val = mtu;
            i_v++;
            printf("MTU: %hu\n", mtu);
            *values = v;

        } else {
            /* ipv4 and ipv6 nested containers not implemented in this example */
            *values = NULL;
            values_cnt = 0;
        }
        printf("Data for '%s' requested.\n", xpath);

    }

    return SR_ERR_OK;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    sr_log_stderr(SR_LL_DBG);

    printf("sr_plugin_init_cb\n");

    rc = sr_module_change_subscribe(session, "ietf-interfaces", module_change_cb, NULL,
                                    0, SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    struct plugin_ctx *ctx = calloc(1, sizeof(*ctx));
    struct list_head interfaces = LIST_HEAD_INIT(interfaces);
    ctx->interfaces = &interfaces;
    ls_interfaces(ctx);

    printf("print interface list\n");
    struct if_interface *iff;
    list_for_each_entry(iff, ctx->interfaces, head) {
        printf("Interface: %s\n", iff->name);
    }

    init_config(ctx);
    sysrepo_commit_network(session, ctx);
    /* rc = sr_dp_get_items_subscribe(session, "/ietf-interfaces:interfaces-state", data_provider_cb, NULL, */
    /*                                SR_SUBSCR_DEFAULT, &subscription); */
    /* if (SR_ERR_OK != rc) { */
    /*     fprintf(stderr, "Error by sr_dp_get_items_subscribe: %s\n", sr_strerror(rc)); */
    /*     goto error; */
    /* } */

    SRP_LOG_DBG_MSG("Plugin initialized successfully");
    *private_ctx = ctx;

    return SR_ERR_OK;

  error:
    SRP_LOG_ERR("Plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    if (!private_ctx) return;

    struct plugin_ctx *ctx = private_ctx;
    sr_unsubscribe(session, ctx->subscription);
    if (ctx->subscription) free(ctx->subscription);
    free(ctx);
}

#ifdef TESTS
volatile int exit_application = 0;

static void
sigint_handler(int signum)
{
    fprintf(stderr, "Sigint called, exiting...\n");
    exit_application = 1;
}

int
main(int argc, char *argv[])
{
    fprintf(stderr, "Plugin test mode initialized\n");
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect("sip", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    void *private_ctx = NULL;
    sr_plugin_init_cb(session, &private_ctx);

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1);  /* or do some more useful work... */
    }

  cleanup:
    sr_plugin_cleanup_cb(session, private_ctx);
}
#endif
