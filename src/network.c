/* Author: Antonio Paunovic <antonio.paunovic@sartura.hr> */

#include <stdio.h>
#include <syslog.h>

#include "network.h"
#include "scripts.h"
#include "common.h"

#define MODULE "/ietf-ip"

struct list_head interfaces = LIST_HEAD_INIT(interfaces);

static int sysrepo_to_model(sr_session_ctx_t *sess, struct plugin_ctx *ctx);
static int model_to_uci(struct plugin_ctx *ctx);

/* Create single ipv4 interface with a give name. */
static struct if_interface *
make_interface_ipv4(char *name)
{
  struct if_interface *interface;

  interface = calloc(1, sizeof(*interface));
  interface->name = strdup(name); //calloc(1, MAX_INTERFACE_NAME);
  /* interface->type = calloc(1, MAX_INTERFACE_TYPE); */
  interface->description = calloc(1, MAX_INTERFACE_DESCRIPTION);
  interface->proto.ipv4 = calloc(1, sizeof(struct ip_v4));

  return interface;

error:
  free(interface);
  return NULL;
}


/* Find available interfaces on the system and fill run-time model with it. */
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
          INF("Found network interface %d: %s %lu", iface->ifi_index, iff->name, iff);
      }

      hdr = RTA_NEXT(hdr, remaining);
  }

  return NL_OK;
}


/* Fill rtnl_neigh structure with MAC and IP addresses. */
static void
neighbor_get_addr_cb(struct nl_object *obj, void *arg)
{
  struct nl_addr *lladdr;
  struct nl_addr *ipaddr;
  struct rtnl_neigh *neigh = (struct rtnl_neigh *) obj;
  struct neighbor_v4 *plugin_neigh = (struct neighbor_v4 *) arg;
  char buf[MAX_ADDR_LEN];

  lladdr = rtnl_neigh_get_lladdr(neigh);
  SR_CHECK_NULL_RETURN_VOID(lladdr, "Can't get phys address");

  ipaddr = rtnl_neigh_get_dst(neigh);
  SR_CHECK_NULL_RETURN_VOID(ipaddr, "Can't get ip address");

  plugin_neigh->link_layer_address = nl_addr2str(lladdr, buf, MAX_ADDR_LEN);
  plugin_neigh->ip = nl_addr2str(ipaddr, buf, MAX_ADDR_LEN);

  return;
}


/* Fill rt model with list of neighbors. */
static void
neighbor_get_addr(struct neighbor_v4 *neighbor)
{
  struct nl_cache *neighbor_cache;
  struct nl_sock *sock;
  int rc;

  sock = nl_socket_alloc();
  if (sock == NULL) {
      fprintf(stderr, "neighbor socket init failed");
      return;
  }

  rc = nl_connect(sock, NETLINK_ROUTE);
  SR_CHECK_RET_MSG(rc, exit, "neighbor socket connect failed");

  rc = rtnl_neigh_alloc_cache(sock, &neighbor_cache);
  SR_CHECK_RET_MSG(rc, exit, "neighbor cache init failed");

  nl_cache_foreach(neighbor_cache, neighbor_get_addr_cb, neighbor);

exit: return;
}


/* Find interface type using interface name. */
static void
find_interface_type(struct uci_context *uctx, char *ifname, char **if_type)
{
  int rc = UCI_OK;
  char path[MAX_UCI_PATH];
  struct uci_element *e;
  struct uci_section *s;
  struct uci_option *o;
  struct uci_ptr ptr;
  struct uci_package *up;
  char *path_fmt = "network.%s.ipaddr=%s"; /* Section and value */

  rc = uci_load(uctx, "network", &up);
  UCI_CHECK_RET(rc, error, "Loading 'network' package failed %d", rc);

  if (UCI_OK != rc) {
      WRN("Cant find package network %s %s", ifname, strerror(rc));
      goto error;
  }
  uci_foreach_element(&up->sections, e) {

      s =  uci_to_section(e);
      if (!s) {
          fprintf(stderr, "no output for this section\n");
          continue;
      }

      o = uci_lookup_option(uctx, s, "ifname");

      if (o && (0 == strcmp(ifname, o->v.string))) {                /* interface name found */
          INF("interface type is %s : %s [%s]\n", s->e.name, o->v.string, ifname);
          *if_type = strdup(s->e.name);
          break;
      }
  }

error:
  if (up) {
      uci_unload(uctx, up);
      INF_MSG("UCI unloaded.");
  }

  return NULL;
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

static void
print_change(sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val)
{
  switch(op) {
  case SR_OP_CREATED:
      if (NULL != new_val) {
          printf("CREATED: ");
          sr_print_val(new_val);
      }
      break;
  case SR_OP_DELETED:
      if (NULL != old_val) {
          printf("DELETED: ");
          sr_print_val(old_val);
      }
      break;
  case SR_OP_MODIFIED:
      if (NULL != old_val && NULL != new_val) {
          printf("MODIFIED: ");
          printf("old value ");
          sr_print_val(old_val);
          printf("new value ");
          sr_print_val(new_val);
      }
      break;
  case SR_OP_MOVED:
      if (NULL != new_val) {
          printf("MOVED: %s after %s", new_val->xpath, NULL != old_val ? old_val->xpath : NULL);
      }
      break;
  }
}


/* Restart network given time to wait before calling script.
* Function is parameterized with number of seconds to enable
* waiting for Sysrepo and UCI to sync.
*/
static void
restart_network(int wait_time)
{
  pid_t restart_pid;

  restart_pid = fork();
  if (restart_pid > 0) {
      INF("[pid=%d] Restarting network in %d seconds after module is changed.", restart_pid, wait_time);
      sleep(wait_time);
      execv("/etc/init.d/network", (char *[]){ "/etc/init.d/network", "restart", NULL });
      exit(0);
  } else {
      INF("[pid=%d] Could not execute network restart, do it manually?", restart_pid);
  }
}


static void
print_current_config(sr_session_ctx_t *session, const char *module_name)
{
  sr_val_t *values = NULL;
  size_t count = 0;
  int rc = SR_ERR_OK;
  char select_xpath[XPATH_MAX_LEN];
  snprintf(select_xpath, XPATH_MAX_LEN, "/%s:*//*", module_name);

  rc = sr_get_items(session, select_xpath, &values, &count);
  if (SR_ERR_OK != rc) {
      printf("Error by sr_get_items: %s", sr_strerror(rc));
      return;
  }
  for (size_t i = 0; i < count; i++){
      sr_print_val(&values[i]);
      }
    sr_free_values(values, count);
}


/* Text representation of Sysrepo event code. */
const char *
ev_to_str(sr_notif_event_t ev) {
    switch (ev) {
    case SR_EV_VERIFY:
        return "verify";
    case SR_EV_APPLY:
        return "apply";
    case SR_EV_ABORT:
    default:
        return "abort";
    }
}


/* On module change following should happen:
 * Verify event is returned, no custom verification is done.
 * On apply event, model is updated from Sysrepo.
 * UCI config is updated from model.
 * Network is restarted so UCI configuration is applied.
 */
static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char change_path[XPATH_MAX_LEN] = {0,};
    struct plugin_ctx *ctx = private_ctx;
    printf("private ctx %lu %lu %s\n", ctx->interfaces, private_ctx, ctx->key);

    if (SR_EV_VERIFY == event) {
        INF_MSG("Verify callback returns OK.");
        return SR_ERR_OK;
    }

    if (SR_EV_APPLY == event) {
        INF_MSG("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n");
        print_current_config(session, module_name);
    }

    INF_MSG("List intefaces in modulechangecb");
    struct if_interface *iff;
    list_for_each_entry(iff, ctx->interfaces, head) {
        printf("Interface: %s %lu\n", iff->name, iff);
    }

    /* snprintf(change_path, XPATH_MAX_LEN, "/%s:*", module_name); */

    /* rc = sr_get_changes_iter(session, change_path , &it); */
    /* if (SR_ERR_OK != rc) { */
    /*     ERR("Get changes iter failed for xpath %s", change_path); */
    /*     goto cleanup; */
    /* } */

    /* while (SR_ERR_OK == (rc = sr_get_change_next(session, it, */
    /*                                              &oper, &old_value, &new_value))) { */
    /*     print_change(oper, old_value, new_value); */

    /*     if (oper == SR_OP_MODIFIED || oper == SR_OP_CREATED) { */

    /*         /\* bool eq = sr_xpath_node_name_eq(new_value->xpath, "type"); *\/ */
    /*         fprintf(stderr, "enabled chaged? %s\n", sr_xpath_node_name(new_value->xpath)); */

    /*         uint16_t mtu_new = new_value->data.uint16_val; /\* for testing purposes *\/ */

    /*         /\* if ((SR_EV_VERIFY == event) && (mtu_new > 1600 || mtu_new < 1000)) { *\/ */
    /*         /\*     return SR_ERR_VALIDATION_FAILED; *\/ */
    /*         /\* } *\/ */
    /*         if (SR_EV_ABORT == event) { */
    /*             fprintf(stderr, "\nCUSTOM WARNING: Please set mtu between 1000 and 1600.\n"); */
    /*         } */
    /*     } */

    /*     sr_free_val(old_value); */
    /*     sr_free_val(new_value); */
    /* } */

    rc = sysrepo_to_model(session, ctx);
    SR_CHECK_RET(rc, exit, "sysrepo_to_model fail: %d", rc);

    rc = model_to_uci(ctx);
    UCI_CHECK_RET(rc, exit, "model_to_uci fail: %d", rc);

    fprintf(stderr, "\n\n ========== END OF CHANGES =======================================\n\n");

    /* Restart network to apply changes. */
    restart_network(RESTART_TIME_TO_WAIT);

    return SR_ERR_OK;
  exit:
    ERR("Changes not applied: %d", rc);

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
        return -1;
    }

    rc = pclose(fp);

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

/*
 * Takes configuration from the datastore and fills in the context.
 */
static int
sysrepo_to_model(sr_session_ctx_t *sess, struct plugin_ctx *ctx)
{
    char xpath[XPATH_MAX_LEN];
    sr_val_t *val= NULL;
    int rc = SR_ERR_OK;
    const char *xpath_fmt = "/ietf-interfaces:interfaces/interface[name='%s']/%s";
    const char *xpath_fmt_ipv4 = "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/%s";
    SRP_LOG_DBG_MSG("Sysrepo get config");

    INF_MSG("List intefaces in sysrepo_to_model");
    struct if_interface *iff;
    list_for_each_entry(iff, ctx->interfaces, head) {
        printf("Interface: %s\n", iff->name);
    }


    struct if_interface *iface;
    list_for_each_entry(iface, ctx->interfaces, head) {
        if (!iface) { WRN_MSG("FUCK no interface in interface?"); break; }
        if (!iface->name) { WRN_MSG("Interface has no name!"); continue; }
        INF("Updating model - interface %s", iface->name);

        /* enabled */
        sprintf(xpath, xpath_fmt_ipv4, iface->name, "enabled");
        rc = sr_get_item(sess, xpath, &val);
        if (SR_ERR_OK == rc) {
            iface->proto.ipv4->enabled = val->data.bool_val;
        } else {
            INF("No enabled for interface %s", iface->name);
        }


        /* forwarding */
        sprintf(xpath, xpath_fmt_ipv4, iface->name, "forwarding");
        rc = sr_get_item(sess, xpath, &val);
        if (SR_ERR_OK == rc) {
            iface->proto.ipv4->forwarding = val->data.bool_val;
        } else {
            INF("No forwarding for interface %s", iface->name);
        }

        /* origin */
        sprintf(xpath, xpath_fmt_ipv4, iface->name, "origin");
        rc = sr_get_item(sess, xpath, &val);
        if (SR_ERR_OK == rc) {
            iface->proto.ipv4->origin = string_to_origin(val->data.enum_val);
        }

        /* MTU */
        sprintf(xpath, xpath_fmt_ipv4, iface->name, "mtu");
        rc = sr_get_item(sess, xpath, &val);
        if (SR_ERR_OK == rc) {
            iface->proto.ipv4->mtu = val->data.uint16_val;
        } else {
            INF("No MTU for interface %s", iface->name);
        }

        /* name */
        sprintf(xpath, xpath_fmt_ipv4, iface->name, "ifname");
        rc = sr_get_item(sess, xpath, &val);
        if (SR_ERR_OK == rc) {
          WRN("ifname: %s", val->data.string_val);
          iface->name = strdup(val->data.string_val);
        } else {
          INF("No IFNAME for interface %s", iface->name);
        }



        /* printf("sysrepo_to_model new mtu %d\n", iface->proto.ipv4->mtu); */

        /* /\* ip *\/ */
        /* sprintf(xpath, xpath_fmt_ipv4, iface->name, "address[ip='%s']/ip"); */
        /* sprintf(xpath, xpath, iface->name, iface->proto.ipv4->address.ip); */
        /* rc = sr_get_item(sess, xpath, &val); */
        /* if (SR_ERR_OK == rc) { */
        /*     strcpy(iface->proto.ipv4->address.ip, val->data.string_val); */
        /* } */

        /* /\* prefix length *\/ */
        /* sprintf(xpath, xpath_fmt_ipv4, iface->name, "address[ip='%s']/prefix_length"); */
        /* sprintf(xpath, xpath, iface->name, iface->proto.ipv4->address.subnet.prefix_length); */
        /* rc = sr_get_item(sess, xpath, &val); */
        /* if (SR_ERR_OK == rc) { */
        /*     iface->proto.ipv4->address.subnet.prefix_length = val->data.uint8_val; */
        /* } */

        /* TODO neighbor */

        if (val) {
            sr_free_val(val);
        }
    }

    INF_MSG("Sysrepo get config end");
    return SR_ERR_OK;
}

/* Apply functions to update the system with data from run-time context. */
/* Only options in UCI can be changed. */
static int
model_to_uci(struct plugin_ctx *ctx)
{
    int rc = UCI_OK;
    struct uci_package *package = NULL;

    INF_MSG("========= MODEL TO UCI ==");

    /* rc = uci_load(ctx->uctx, "network", &package); */
    /* UCI_CHECK_RET(rc, exit, "uci_load fail: %d", rc); */

    struct if_interface *iface;
    list_for_each_entry(iface, ctx->interfaces, head) {
        if (!iface->type) {
          WRN("model_to_uci no type for interface %s, %s", iface->name, iface->type);
            continue;
        }
        WRN("model_to_uci  type for interface %s is %lu %s", iface->name, iface->type, iface->type); 
        /* struct rtnl_link *link = rtnl_link_get_by_name(ctx->fctx->cache_link, iface->name); */

        /* enabled */
        /* set_operstate(ctx->uctx, iface->name, iface->proto.ipv4->enabled); */

        /* name */
        set_name(ctx->uctx, iface->type, iface->name);

        /* forwarding */
        /* set_forwarding(link, iface->proto.ipv4->forwarding); */

        /* origin */
        /* set_origin(link, iface->proto.ipv4->origin); */

        /* MTU */
        set_mtu(ctx->uctx, iface->type, iface->proto.ipv4->mtu);

        /* ip */
        /* set_ip4(ctx->uctx, iface->name, iface->proto.ipv4->address.ip); */

        /* prefix length */
        /* set_prefix_length(link, iface->proto.ipv4->address.subnet.prefix_length); */
        /* TODO neighbor */

     }

    /* INF_MSG("UCI commiting"); */
    /* rc = uci_commit(ctx->uctx, &package, false); */
    /* UCI_CHECK_RET(rc, exit, "uci_commit fail: %d", rc); */

    INF_MSG("UCI commited.");
    /* sr  commit */
    /* uci commit */
    /* uci_unload(ctx->uctx, package); */

  exit:
    return rc;
}

/* Fill running datastore with run-time context information. */
static int
sysrepo_commit_network(sr_session_ctx_t *sess, struct plugin_ctx *ctx)
{
    char xpath[XPATH_MAX_LEN];
    const char *xpath_fmt = "/ietf-interfaces:interfaces/interface[name='%s']/%s";
    const char *xpath_fmt_ipv4 = "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/%s";
    int rc = SR_ERR_OK;
    sr_val_t val = { 0 };
    SRP_LOG_DBG_MSG("Sysrepo commit network");

    struct if_interface *iface;
    list_for_each_entry(iface, ctx->interfaces, head) {
        printf("to commit %s\n", iface->name);
        if (strcmp(iface->name, "eth1")) { continue; };

        sprintf(xpath, xpath_fmt, iface->name, "type");
        val.type = SR_IDENTITYREF_T;
        val.data.identityref_val = "iana-if-type:ethernetCsmacd";
        sr_val_set_xpath(&val, xpath);
        fprintf(stderr, "== Sysrepo commit network - set_item %s\n", xpath);
        sr_print_val_stream(stderr, &val);
        rc = sr_set_item(sess, xpath, &val, SR_EDIT_DEFAULT);

        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error by sr_set_item: %s for %s\n", sr_strerror(rc), xpath);
            goto cleanup;
        }

        /* Set forwarding. */
        val.type = SR_BOOL_T;
        val.data.bool_val = iface->proto.ipv4->forwarding;
        sprintf(xpath, xpath_fmt_ipv4, iface->name, "forwarding");
        rc = sr_set_item(sess, xpath,
                         &val, SR_EDIT_DEFAULT);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error by sr_set_item: %s\n", sr_strerror(rc));
            goto cleanup;
        }

        /* set MTU. */
        val.type = SR_UINT16_T;
        val.data.uint16_val = iface->proto.ipv4->mtu;
        sprintf(xpath, xpath_fmt_ipv4, iface->name, "mtu");
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
init_config_ipv4(struct ip_v4 *ipv4, char *interface_name)
{
    struct function_ctx *fun_ctx;
    char buf[BUFSIZE];
    int rc = 0;

    fun_ctx = make_function_ctx();

    printf("rtnl_link_get_by_name\n");

    struct rtnl_link *link = rtnl_link_get_by_name(fun_ctx->cache_link, interface_name);
    if (link == NULL) {
        fprintf(stderr, "failed to get link\n");
        goto error;
    }

    // IP
    strcpy(ipv4->address.ip, get_ip4(fun_ctx, link));

    // MTU
    ipv4->mtu = get_mtu(link);

    /* // ENABLED (operstate?) */
    /* ipv4->enabled = !strcmp(get_operstate(link), "UP") ? true : false; */

    /* // PREFIX LENGTH */
    /* ipv4->address.subnet.prefix_length = init_prefixlen(fun_ctx); */

    /* // FORWARDING */
    /* ipv4->forwarding = init_forwarding(link); */

    /* // ORIGIN (uci) */
    /* rc = str_from_cmd(cmd_origin, interface_name, "%s", buf); */
    /* if (rc == 0) { */
    /*     ipv4->origin = string_to_origin(buf); */
    /* } else { */
    /*     fprintf(stderr, "No 'origin' in uci file.\n"); */

    /* } */


    free_function_ctx(fun_ctx);
    return 0;

  error:
    free_function_ctx(fun_ctx);
    return -1;
}

static int
init_config(struct plugin_ctx *ctx)
{
    char *type;
    struct if_interface *iface;

    list_for_each_entry(iface, ctx->interfaces, head) {
        INF_MSG()
        if (iface->proto.ipv4) {
            init_config_ipv4(iface->proto.ipv4, iface->name);
            find_interface_type(ctx->uctx, iface->name, &iface->type);
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
    /* sr_xpath_ctx_t xp_ctx = {0}; */
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
            printf("speed %lu\n", speed);
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

    /* INF("sr_plugin_init_cb for sysrepo-plugin-dt-network"); */

    struct plugin_ctx *ctx = calloc(1, sizeof(*ctx));
    ctx->key = "bla";
    ctx->interfaces = &interfaces;
    ls_interfaces(ctx);

    /* Allocate UCI context for uci files. */
    ctx->uctx = uci_alloc_context();
    if (!ctx->uctx) {
        fprintf(stderr, "Can't allocate uci\n");
        goto error;
    }
    INF("UCI ALLOCATED %l", ctx->uctx);

    init_config(ctx);
    INF_MSG("init config finish\n");
    /* sysrepo_commit_network(session, ctx); */
    INF_MSG("sysrepo commit finish\n");


    /* rc = sr_dp_get_items_subscribe(session, "/ietf-interfaces:interfaces-state", data_provider_cb, *private_ctx, */
    /*                                SR_SUBSCR_DEFAULT, &subscription); */
    /* if (SR_ERR_OK != rc) { */
    /*     fprintf(stderr, "Error by sr_dp_get_items_subscribe: %s\n", sr_strerror(rc)); */
    /*     goto error; */
    /* } */

    *private_ctx = ctx;
    INF("Private context %lu %lu\n", *private_ctx, ctx);

    rc = sr_module_change_subscribe(session, "ietf-interfaces", module_change_cb, *private_ctx,
                                    0, SR_SUBSCR_DEFAULT, &subscription);
    SR_CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

    /* set_mtu(ctx->uctx, "wan6", 1470u); */

    SRP_LOG_DBG_MSG("Plugin initialized successfully");
    struct if_interface *iff;
    list_for_each_entry(iff, ctx->interfaces, head) {
        printf("Interface: %s %lu %s\n", iff->name, iff, iff->type);
    }
    printf("private ctx %lu %lu\n", ctx, ctx->interfaces);


    return SR_ERR_OK;

  error:
    SRP_LOG_ERR("Plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    free(ctx);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    INF("Plugin cleanup called %lu", private_ctx);
    if (!private_ctx) return;

    struct plugin_ctx *ctx = private_ctx;
    sr_unsubscribe(session, ctx->subscription);
    if (ctx->subscription) free(ctx->subscription);
    free_function_ctx(ctx->fctx);
    free(ctx);

    SRP_LOG_DBG_MSG("Plugin cleaned-up successfully");
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
