===========
 iwd.debug
===========

-----------------------------------------
Debugging information for wireless daemon
-----------------------------------------

:Author: Marcel Holtmann <marcel@holtmann.org>
:Author: Denis Kenzior <denkenz@gmail.com>
:Author: Andrew Zaborowski <andrew.zaborowski@intel.com>
:Author: Tim Kourt <tim.a.kourt@linux.intel.com>
:Author: James Prestwood <prestwoj@gmail.com>
:Copyright: 2013-2019 Intel Corporation
:Version: iwd
:Date: 22 September 2019
:Manual section: 7
:Manual group: Linux Connectivity

SYNOPSIS
========

Debugging information for wireless daemon

DESCRIPTION
===========

Common methods of obtaining extra debugging information.

ENVIRONMENT
===========

*$IWD_RTNL_DEBUG* set to ``1`` enables RTNL debugging.

*$IWD_GENL_DEBUG* set to ``1`` enables printing Generic Netlink communication with the kernel.

*$IWD_DHCP_DEBUG* set to ``1`` enables DHCP debugging.

*$IWD_TLS_DEBUG* set to ``1`` enables TLS debugging.

*$IWD_WSC_DEBUG_KEYS* set to ``1`` enables printing received WSC keys.

The granularity of the DHCP logging can also be tailored by setting
*$IWD_DHCP_DEBUG* to the maximum verbosity level, "debug", "info", "warn", or
"error".

SEE ALSO
========

iwd(8), iwmon(1)
