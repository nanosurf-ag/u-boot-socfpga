/*
 *	Copyied from bootp.*, edit for Nanosurf AG made by Adrian Rudin, Daniel Friedrich
 *
 *	Copyright 1994, 1995, 2000 Neil Russell.
 *	(See License)
 *	Copyright 2000 Paolo Scaffardi
 */

#ifndef __NSFBOOTP_H__
#define __NSFBOOTP_H__

#ifndef __NET_H__
#include <net.h>
#endif /* __NET_H__ */

/**********************************************************************/

/*
 *	NSFBOOTP header.
 */
#define NSFOPT_FIELD_SIZE 64

struct nsfbootp_hdr {
	u8		bp_op;		/* Operation			*/
# define OP_BOOTREQUEST	1
# define OP_BOOTREPLY	2
	u8		bp_htype;	/* Hardware type		*/
# define HWT_ETHER	1
	u8		bp_hlen;	/* Hardware address length	*/
# define HWL_ETHER	6
	u8		bp_hops;	/* Hop count (gateway thing)	*/
	u32		bp_id;		/* Transaction ID		*/
	u16		bp_secs;	/* Seconds since boot		*/
	u16		bp_cmd;	/* Command			*/
# define CMD_NO_OP 0
# define CMD_USING_DHCP 1
# define CMD_USING_STATIC 2
# define CMD_SWITCH_TO_DHCP 3
# define CMD_SWITCH_TO_STATIC 4
	struct in_addr	bp_ip_addr;	/* Client IP address		*/
	struct in_addr	bp_net_mask;	/* Your (client) IP address	*/
	struct in_addr	bp_server_addr;	/* Server IP address		*/
	struct in_addr	bp_gateway_addr;	/* Gateway IP address		*/
	u8		bp_chaddr[16];	/* Client hardware address	*/
	char		bp_sname[64];	/* Server host name		*/
	char		bp_file[128];	/* Boot file name		*/
	char		bp_vend[NSFOPT_FIELD_SIZE]; /* Ven information	*/
} __attribute__((packed));

#define NSFBOOTP_HDR_SIZE	sizeof(struct nsfbootp_hdr)

/**********************************************************************/
/*
 *	Global functions and variables.
 */
void nsfbootp_reset(void);
void nsfbootp_request(void);

/**********************************************************************/

#endif /* __NSFBOOTP_H__ */
