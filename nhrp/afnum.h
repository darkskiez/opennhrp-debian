/* afnum.h - RFC 1700 Address Family Number and
 *           ethernet protocol number definitions
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 or later as
 * published by the Free Software Foundation.
 *
 * See http://www.gnu.org/ for details.
 */

#ifndef AFNUM_H
#define AFNUM_H

#include <linux/if_ether.h>
#include "nhrp_defines.h"

#define AFNUM_RESERVED		constant_htons(0)
#define AFNUM_INET		constant_htons(1)
#define AFNUM_INET6		constant_htons(2)

#define ETH_P_NHRP		0x2001

#define ETHPROTO_IP		constant_htons(ETH_P_IP)
#define ETHPROTO_NHRP		constant_htons(ETH_P_NHRP)

#endif
