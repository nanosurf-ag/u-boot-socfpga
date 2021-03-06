/*
  *	Copyied from bootp.*, edit for Nanosurf AG made by Adrian Rudin, Daniel Friedrich
 *
 *	Copyright 1994, 1995, 2000 Neil Russell.
 *	(See License)
 *	Copyright 2000 Roland Borde
 *	Copyright 2000 Paolo Scaffardi
 *	Copyright 2000-2004 Wolfgang Denk, wd@denx.de
 */

#include <common.h>
#include <environment.h>

#include "nsfbootp.h"

#define PORT_NSFBOOTPS	33067		/* NSFBOOTP server UDP port */
#define PORT_NSFBOOTPC	33068		/* NSFBOOTP client UDP port */

#ifndef CONFIG_BOOTP_ID_CACHE_SIZE
#define CONFIG_BOOTP_ID_CACHE_SIZE 4
#endif

#define BP_FLAG_BIT_MASK_IS_STATIC 0x01

u32		nsfbootp_ids[CONFIG_BOOTP_ID_CACHE_SIZE];
unsigned int	nsfbootp_num_ids;
int		nsfbootp_try;
ulong		nsfbootp_start;
ulong		nsfbootp_timeout;
bool		nsfbootp_require_reboot;
bool		nsfbootp_boot_os;
/* global reset function */
extern int do_reset(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[]);

static void nsfbootp_reboot(void)
{
	do_reset(NULL, 0,0, NULL);
}

static void bootp_add_id(ulong id)
{
	if (nsfbootp_num_ids >= ARRAY_SIZE(nsfbootp_ids)) {
		size_t size = sizeof(nsfbootp_ids) - sizeof(id);

		memmove(nsfbootp_ids, &nsfbootp_ids[1], size);
		nsfbootp_ids[nsfbootp_num_ids - 1] = id;
	} else {
		nsfbootp_ids[nsfbootp_num_ids] = id;
		nsfbootp_num_ids++;
	}
}

static bool bootp_match_id(ulong id)
{
	unsigned int i;

	for (i = 0; i < nsfbootp_num_ids; i++)
		if (nsfbootp_ids[i] == id)
			return true;

	return false;
}

static int check_reply_packet(uchar *pkt, unsigned dest, unsigned src,
			      unsigned len)
{
	struct nsfbootp_hdr *bp = (struct nsfbootp_hdr *)pkt;
	int retval = 0;

	if (dest != PORT_NSFBOOTPC || src != PORT_NSFBOOTPS)
		retval = -1;
	else if (len < sizeof(struct nsfbootp_hdr) - NSFOPT_FIELD_SIZE)
		retval = -2;
	else if (bp->bp_op != OP_BOOTREPLY && bp->bp_op != OP_SETNETWORK)
		retval = -3;
	else if (bp->bp_htype != HWT_ETHER)
		retval = -4;
	else if (bp->bp_hlen != HWL_ETHER)
		retval = -5;
	else if (!bootp_match_id(net_read_u32(&bp->bp_id)))
		retval = -6;
	else if (memcmp(bp->bp_chaddr, net_ethaddr, HWL_ETHER) != 0)
		retval = -7;

	//printf("NSFBOOTP store_net_params Filtering pkt = %d\n", retval);

	return retval;
}

static void store_net_params_static(struct nsfbootp_hdr *bp)
{
	printf("NSFBOOTP change network settings to static\n");
	char tmp[22];

	env_set("nsf_use_static", "1");

	ip_to_string(bp->bp_ip_addr, tmp);
	printf("NSFBOOTP nsf_static_ipaddr = %s\n", tmp);
	env_set("nsf_static_ipaddr", tmp);

	ip_to_string(bp->bp_net_mask, tmp);
	printf("NSFBOOTP nsf_static_netmask = %s\n", tmp);
	env_set("nsf_static_netmask", tmp);

	ip_to_string(bp->bp_gateway_addr, tmp);
	printf("NSFBOOTP nsf_static_gatewayip = %s\n", tmp);
	env_set("nsf_static_gatewayip", tmp);

	nsfbootp_require_reboot = true;
}

static void store_net_params_automatic(struct nsfbootp_hdr *bp)
{
	printf("NSFBOOTP change network settings to automatic (dhcp/zeroconf)\n");

	env_set("nsf_use_static", "0");

	nsfbootp_require_reboot = true;
}

static void store_server_address(struct nsfbootp_hdr *bp)
{
	struct in_addr tmp_ip;
	net_copy_ip(&tmp_ip, &bp->bp_server_addr);

	if (tmp_ip.s_addr != 0 && !net_server_ip.s_addr)
		net_copy_ip(&net_server_ip, &bp->bp_server_addr);

	memcpy(net_server_ethaddr,
		((struct ethernet_hdr *)net_rx_packet)->et_src, 6);
}

static void store_boot_file(struct nsfbootp_hdr *bp)
{
	if ((strlen(bp->bp_file) > 0) && !net_boot_file_name_explicit) {
		copy_filename(net_boot_file_name, bp->bp_file,
			      sizeof(net_boot_file_name));
	}

	if (*net_boot_file_name)
		env_set("bootfile", net_boot_file_name);
}

/*
 * Copy parameters of interest from BOOTP_REPLY/DHCP_OFFER packet
 */
static void store_net_params(struct nsfbootp_hdr *bp) {
	const u16 flags = ntohs(bp->bp_flags);
	const bool is_static_network = flags & BP_FLAG_BIT_MASK_IS_STATIC;

	store_boot_file(bp);
	store_server_address(bp);

	if(bp->bp_op == OP_SETNETWORK) {
		if(is_static_network) {
			store_net_params_static(bp);
		}
		else {
			store_net_params_automatic(bp);
		}
	}
	else if(bp->bp_op == OP_BOOTREPLY){
		nsfbootp_boot_os = true;
	}
}

/*
 *	Handle a BOOTP received packet.
 */
static void bootp_handler(uchar *pkt, unsigned dest, struct in_addr sip,
			  unsigned src, unsigned len)
{
	struct nsfbootp_hdr *bp;
	bp = (struct nsfbootp_hdr *)pkt;

	if (check_reply_packet(pkt, dest, src, len))
		return;
	nsfbootp_require_reboot = false;
	nsfbootp_boot_os = false;

	store_net_params(bp);

	net_set_timeout_handler(0, (thand_f *)0);
	bootstage_mark_name(BOOTSTAGE_ID_BOOTP_STOP, "bootp_stop");

	if(nsfbootp_require_reboot == true) {
		env_save();
		nsfbootp_reboot();
	}
	else if(nsfbootp_boot_os == true) {
		net_auto_load();
	}
}

static void nsfbootp_timeout_handler(void) {
	net_set_timeout_handler(nsfbootp_timeout, nsfbootp_timeout_handler);
	nsfbootp_request();
}

static int add_nsfbootp_vend_payload(u8 *e) {
	char *nsfbootp_vend_payload;
	static const size_t max_str_len = 63;
	static const size_t max_vend_len = 64;

	/* Copy nsfboop_vend_payload env variable into vend field of bootp payload
	 * or "Unkown" if not available */
	nsfbootp_vend_payload = env_get("nsfbootp_vend_payload");
	if (!nsfbootp_vend_payload) {
			nsfbootp_vend_payload = "Unknown";
	}
	size_t nsfbootp_vend_payload_len = max(strlen(nsfbootp_vend_payload), max_str_len);
	memcpy(e, nsfbootp_vend_payload, nsfbootp_vend_payload_len);
	e += nsfbootp_vend_payload_len;

	/* Set rest of vend part to 0 */
	memset(e, 0, max_vend_len - nsfbootp_vend_payload_len);

	return max_vend_len;
}

void nsfbootp_reset(void)
{
	nsfbootp_num_ids = 0;
	nsfbootp_try = 0;
	nsfbootp_start = get_timer(0);
	nsfbootp_timeout = 1000; /* 1000ms retry interval */
	nsfbootp_require_reboot = false;
	nsfbootp_boot_os = false;
}

void nsfbootp_request(void)
{
	uchar *pkt, *iphdr;
	struct nsfbootp_hdr *bp;
	int extlen, pktlen, iplen;
	int eth_hdr_size;
	u32 bootp_id;
	u16 flags;
	struct in_addr bcast_ip;

	bootstage_mark_name(BOOTSTAGE_ID_BOOTP_START, "nsfbootp_start");

	printf("NSFBOOTP broadcast %d\n", ++nsfbootp_try);
	pkt = net_tx_packet;
	memset((void *)pkt, 0, PKTSIZE);

	eth_hdr_size = net_set_ether(pkt, net_bcast_ethaddr, PROT_IP);
	pkt += eth_hdr_size;

	/*
	 * Next line results in incorrect packet size being transmitted,
	 * resulting in errors in some DHCP servers, reporting missing bytes.
	 * Size must be set in packet header after extension length has been
	 * determined.
	 * C. Hallinan, DS4.COM, Inc.
	 */
	/* net_set_udp_header(pkt, 0xFFFFFFFFL, PORT_NSFBOOTPS, PORT_NSFBOOTPC,
		sizeof (struct nsfbootp_hdr)); */
	iphdr = pkt;	/* We need this later for net_set_udp_header() */
	pkt += IP_UDP_HDR_SIZE;

	bp = (struct nsfbootp_hdr *)pkt;
	bp->bp_op = OP_BOOTREQUEST;
	bp->bp_htype = HWT_ETHER;
	bp->bp_hlen = HWL_ETHER;
	bp->bp_hops = 0;
	/*
	 * according to RFC1542, should be 0 on first request, secs since
	 * first request otherwise
	 */
	bp->bp_secs = htons(get_timer(nsfbootp_start) / 1000);

	flags = 0;
	const char* nsf_use_static_str = env_get("nsf_use_static");
	if(strcmp(nsf_use_static_str, "1") == 0) {
		flags |= BP_FLAG_BIT_MASK_IS_STATIC;
	}
	else {
		flags &= ~(BP_FLAG_BIT_MASK_IS_STATIC);
	}
	bp->bp_flags = htons(flags);

	const char* nsf_static_ipaddr_str = env_get("nsf_static_ipaddr");
	const struct in_addr nsf_static_ipaddr = string_to_ip(nsf_static_ipaddr_str);

	const char* nsf_static_netmask_str = env_get("nsf_static_netmask");
	const struct in_addr nsf_static_netmask= string_to_ip(nsf_static_netmask_str);

	const char* nsf_static_gatewayip_str = env_get("nsf_static_gatewayip");
	const struct in_addr nsf_static_gatewayip= string_to_ip(nsf_static_gatewayip_str);

	net_write_ip(&bp->bp_ip_addr, nsf_static_ipaddr);
	net_write_ip(&bp->bp_net_mask, nsf_static_netmask);
	net_write_ip(&bp->bp_gateway_addr, nsf_static_gatewayip);
	net_write_ip(&bp->bp_server_addr, net_server_ip);

	memcpy(bp->bp_chaddr, net_ethaddr, 6);
	copy_filename(bp->bp_file, net_boot_file_name, sizeof(bp->bp_file));

	extlen = add_nsfbootp_vend_payload((u8 *)bp->bp_vend);

	/*
	 *	Bootp ID is the lower 4 bytes of our ethernet address
	 *	plus the current time in ms.
	 */
	bootp_id = ((u32)net_ethaddr[2] << 24)
		| ((u32)net_ethaddr[3] << 16)
		| ((u32)net_ethaddr[4] << 8)
		| (u32)net_ethaddr[5];
	bootp_id += get_timer(0);
	bootp_id = htonl(bootp_id);
	bootp_add_id(bootp_id);
	net_copy_u32(&bp->bp_id, &bootp_id);

	/*
	 * Calculate proper packet lengths taking into account the
	 * variable size of the options field
	 */
	iplen = NSFBOOTP_HDR_SIZE - NSFOPT_FIELD_SIZE + extlen;
	pktlen = eth_hdr_size + IP_UDP_HDR_SIZE + iplen;
	bcast_ip.s_addr = 0xFFFFFFFFL;
	net_set_udp_header(iphdr, bcast_ip, PORT_NSFBOOTPS, PORT_NSFBOOTPC, iplen);
	net_set_timeout_handler(nsfbootp_timeout, nsfbootp_timeout_handler);

	net_set_udp_handler(bootp_handler);
	net_send_packet(net_tx_packet, pktlen);
}
