/* Author: Antonio Paunovic <antonio.paunovic@sartura.hr> */

#include <stdio.h>
#include <syslog.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/genl/genl.h>

#include "network.h"
#include "scripts.h"

#define MODULE "/ietf-ip"
#define XPATH_MAX_LEN 100
#define BUFSIZE 256
#define MAX_INTERFACES 10

static int
callback(struct nl_msg *msg, void *arg) {
    char **iffs = (char **) arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct ifinfomsg *iface = NLMSG_DATA(nlh);
    struct rtattr *hdr = IFLA_RTA(iface);
    int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

    int i = 0;
    while (RTA_OK(hdr, remaining)) {

        if (hdr->rta_type == IFLA_IFNAME) {
            printf("Found network interface %d: %s\n", iface->ifi_index, (char *) RTA_DATA(hdr));
            iffs[i++] = (char *) RTA_DATA(hdr);
        }

        hdr = RTA_NEXT(hdr, remaining);
    }

    return NL_OK;
}

int
ls_interfaces() {
    // Open socket to kernel.
    struct nl_sock *socket = nl_socket_alloc();  // Allocate new netlink socket in memory.
    nl_connect(socket, NETLINK_ROUTE);  // Create file descriptor and bind socket.

    // Send request for all network interfaces.
    struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
    int ret = nl_send_simple(socket, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
    printf("nl_send_simple returned %d\n", ret);

    // Retrieve the kernel's answer.
    char iffs[4][20];
    nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback, iffs);
    nl_recvmsgs_default(socket);

    printf("IFFS: %s\n", iffs[0]);

    return 0;
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
sysrepo_commit_network(sr_session_ctx_t *sess, struct if_interface *iface)
{
    int rc = SR_ERR_OK;
    char xpath[XPATH_MAX_LEN];
    sr_val_t val = { 0 };
    sr_val_t *v = NULL;

    if (iface) {
        /* Set forwarding. */
        val.type = SR_BOOL_T;
        val.data.bool_val = true;
        rc = sr_set_item(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/forwarding",
                         &val, SR_EDIT_DEFAULT);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error by sr_set_item: %s\n", sr_strerror(rc));
            goto cleanup;
        }

        rc = sr_new_values(1, &v);
        sr_val_set_xpath(&v[0], "/ietf-interfaces:interfaces/interface[name='eth0']/type");
        sr_val_set_str_data(&v[0], SR_IDENTITYREF_T, "ethernetCsmacd");
        v[0].type = SR_IDENTITYREF_T;
        /* val.data.identityref_val = "ethernetCsmacd"; */
        rc = sr_set_item(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type",
                         &v[0], SR_EDIT_DEFAULT);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error by sr_set_item: %s\n", sr_strerror(rc));
            goto cleanup;
        }

        /* set MTU. */
        val.type = SR_UINT16_T;
        val.data.uint16_val = iface->ipv4->mtu;
        rc = sr_set_item(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/mtu", &val, SR_EDIT_DEFAULT);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error by sr_set_item: %s\n", sr_strerror(rc));
            goto cleanup;
        }
    }

    /* Commit values set. */
    rc = sr_commit(sess);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_commit: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    return SR_ERR_OK;

  cleanup:
    return rc;
}

static int
init_config(struct ip_v4 *ipv4)
{
    FILE *fp;
    char buf[BUFSIZE];
    char *interface_name = ipv4->address.ip;

    if ((fp = popen(cmd_ip, "r")) == NULL) {
        fprintf(stderr, "Error opening pipe\n");
        return -1;
    }

    if (fgets(buf, BUFSIZE, fp) != NULL) {
        sscanf(buf, "%s", ipv4->address.ip);
    } else {
        fprintf(stderr, "Error getting ip.\n");
    }

    if ((fp = popen(cmd_netmask, "r")) == NULL) {
        fprintf(stderr, "Error opening pipe!\n");
        return -1;
    }

    if (fgets(buf, BUFSIZE, fp) != NULL) {
        sscanf(buf, "%s", ipv4->address.subnet.netmask);
        ipv4->address.subnet.netmask = strdup(buf);
    } else {
        fprintf(stderr, "Error getting netmask.\n");
    }

    pclose(fp);

    int_from_cmd(cmd_mtu, interface_name, "%hu", &ipv4->mtu);
    ipv4->mtu = (unsigned int)ipv4->mtu;
    str_from_cmd(cmd_enabled, interface_name, "%s", buf);
    ipv4->enabled = !strcmp(buf, "UP") ? true : false ;
    int_from_cmd(cmd_forwarding, interface_name, "%d", &ipv4->forwarding);
    str_from_cmd(cmd_origin, interface_name, "%s", buf);
    ipv4->origin = string_to_origin(buf);

    return 0;
}

/* Handle operational data. */
static int
data_provider_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    sr_val_t *v = NULL;
    sr_xpath_ctx_t xp_ctx = {0};
    int i_v = 0;
    int rc = SR_ERR_OK;

    printf("Data for '%s' requested.\n", xpath);

    struct plugin_ctx *ctx = (struct plugin_ctx *) private_ctx;
    char *interface_name = ctx->key; /* PLACEHOLDER */

    if (sr_xpath_node_name_eq(xpath, "interface")) {

        *values_cnt = 4;

        /* allocate space for data to return */
        rc = sr_new_values(*values_cnt, &v);
        if (SR_ERR_OK != rc) {
            return rc;
        }

        sr_val_set_xpath(&v[i_v], "/ietf-interfaces:interfaces-state/interface[name='eth0']/type");
        sr_val_set_str_data(&v[i_v], SR_IDENTITYREF_T, "ethernetCsmacd");
        i_v++;

        printf("i_v %d\n", i_v);
        /* oper-status */
        char buf[BUFSIZE] = { 0 };
        str_from_cmd(cmd_enabled, interface_name, "%s", buf);
        printf("buf %s\n", buf);

        sr_val_set_xpath(&v[i_v], "/ietf-interfaces:interfaces-state/interface[name='eth0']/oper-status");
        sr_val_set_str_data(&v[i_v], SR_ENUM_T, buf);
        i_v++;

        printf("i_v %d\n", i_v);
        /* last change */

        /* phys address */
        str_from_cmd(cmd_mac, interface_name, "%s", buf);
        printf("mac %s\n", buf);
        sr_val_set_xpath(&v[i_v], "/ietf-interfaces:interfaces-state/interface[name='eth0']/phys-address");
        sr_val_set_str_data(&v[i_v], SR_STRING_T, buf);
        i_v++;

        printf("i_v %d\n", i_v);
        /* speed */
        uint64_t speed = 0;
        int_from_cmd(cmd_speed, interface_name, "%lu", &speed);
        printf("speed %llu\n", speed);
        sr_val_set_xpath(&v[i_v], "/ietf-interfaces:interfaces-state/interface[name='eth0']/speed");
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
        sr_val_set_xpath(&v[i_v], "/ietf-interfaces:interfaces-state/interface[name='eth0']/statistics/out-octets");
        v[i_v].type = SR_UINT64_T;
        v[i_v].data.uint64_val = tx;
        i_v++;

        uint32_t tx_err = 0;
        int_from_cmd(cmd_tx_err, interface_name, "%lu", &tx_err);
        sr_val_set_xpath(&v[i_v], "/ietf-interfaces:interfaces-state/interface[name='eth0']/statistics/out-errors");
        v[i_v].type = SR_UINT32_T;
        v[i_v].data.uint32_val = tx_err;
        i_v++;

        uint64_t rx = 0;
        int_from_cmd(cmd_rx, interface_name, "%lu", &rx);
        sr_val_set_xpath(&v[i_v], "/ietf-interfaces:interfaces-state/interface[name='eth0']/statistics/in-octets");
        v[i_v].type = SR_UINT64_T;
        v[i_v].data.uint64_val = rx;
        i_v++;

        uint32_t rx_err = 0;
        int_from_cmd(cmd_rx_err, interface_name, "%lu", &rx_err);
        sr_val_set_xpath(&v[i_v], "/ietf-interfaces:interfaces-state/interface[name='eth0']/statistics/in-errors");
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
        sr_val_set_xpath(&v[i_v], "/ietf-interfaces:interfaces-state/interface[name='eth0']/statistics/ipv4/mtu");
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

    return SR_ERR_OK;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    sr_log_stderr(SR_LL_DBG);

    printf("sr_plugin_init_cb\n");

    /* rc = sr_module_change_subscribe(session, "ietf-interfaces", module_change_cb, NULL, */
    /*                                 0, SR_SUBSCR_DEFAULT, &subscription); */
    /* if (SR_ERR_OK != rc) { */
    /*     goto error; */
    /* } */

    struct plugin_ctx *ctx = calloc(1, sizeof(*ctx));
    struct list_head interfaces = LIST_HEAD_INIT(interfaces);
    struct if_interface *interface = calloc(1, sizeof(*interface));
    interface->ipv4 = calloc(1, sizeof(struct ip_v4));
    list_add(&interface->head, &interfaces);
    struct if_interface *iface;
    list_for_each_entry(iface, &interfaces, head) {

    }
    /* sysrepo_commit_network(session, interface); */

    ls_interfaces();
    SRP_LOG_DBG_MSG("Plugin initialized successfully");


  /*   rc = sr_dp_get_items_subscribe(session, "/ietf-interfaces:interfaces-state", data_provider_cb, NULL, */
  /*                                  SR_SUBSCR_DEFAULT, &subscription); */
  /*   if (SR_ERR_OK != rc) { */
  /*       fprintf(stderr, "Error by sr_dp_get_items_subscribe: %s\n", sr_strerror(rc)); */
  /*       goto error; */
  /*   } */

  /*   /\* set subscription as our private context *\/ */
  /*   *private_ctx = subscription; */

  /*   return SR_ERR_OK; */

  error:
  /*   SRP_LOG_ERR("Plugin initialization failed: %s", sr_strerror(rc)); */
  /*   sr_unsubscribe(session, subscription); */
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    struct plugin_ctx *ctx = private_ctx;
    if (ctx->subscription) free(ctx->subscription);
    free(ctx->key);
    free(ctx);
    sr_unsubscribe(session, private_ctx);
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
        sleep(1000);  /* or do some more useful work... */
    }

  cleanup:
    sr_plugin_cleanup_cb(session, private_ctx);
}
#endif
