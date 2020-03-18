============
 iwd.config
============

--------------------------------------
Configuration file for wireless daemon
--------------------------------------

:Author: Marcel Holtmann <marcel@holtmann.org>
:Author: Denis Kenzior <denkenz@gmail.com>
:Author: Andrew Zaborowski <andrew.zaborowski@intel.com>
:Author: Tim Kourt <tim.a.kourt@linux.intel.com>
:Author: James Prestwood <prestwoj@gmail.com>
:Copyright: 2013-2019 Intel Corporation
:Version: iwd
:Date: 22 September 2019
:Manual section: 5
:Manual group: Linux Connectivity

SYNOPSIS
========

Configuration file **main.conf**

DESCRIPTION
===========

The *main.conf* configuration file configures the system-wide settings for
**iwd**.  This file lives in the configuration directory specified by the
environment variable *$CONFIGURATION_DIRECTORY*, which is normally provided
by **systemd**.  In the absence of such an environment variable it defaults
to */etc/iwd*.  If no *main.conf* is present, then default values are
chosen.  The presence of *main.conf* is not required.

FILE FORMAT
===========

See *iwd.network* for details on the file format.

SETTINGS
========

The settings are split into several categories.  Each category has a group
associated with it and described in separate tables below.

General Settings
----------------

The group ``[General]`` contains general settings.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - EnableNetworkConfiguration
     - Values: true, **false**

       Enable network configuration.

       Setting this option to *true* enables **iwd** to configure the network
       interfaces with the IP addresses.  There are two types IP addressing
       supported by **iwd**: static and dynamic.  The static IP addresses are
       configured through the network configuration files.  If no static IP
       configuration has been provided for a network, **iwd** will attempt to
       obtain the dynamic addresses from the network through the built-in
       DHCP client.

       The network configuration feature is disabled by default.  See
       ``[Network]`` settings for additional settings related to network
       configuration.

   * - UseDefaultInterface
     - Values: true, **false**

       Do not allow **iwd** to destroy / recreate wireless interfaces at
       startup, including default interfaces.  Enable this behavior if your
       wireless card driver is buggy or does not allow such an operation, or
       if you do not want **iwd** to manage netdevs for another reason.  For
       most users with an upstream driver it should be safe to omit/disable
       this setting.

   * - AddressRandomization
     - Values: **disabled**, once, network

       If ``AddressRandomization`` is set to ``disabled``, the default kernel
       behavior is used.  This means the kernel will assign a mac address from
       the permanent mac address range provided by the hardware / driver.  Thus
       it is possible for networks to track the user by the mac address which
       is permanent.

       If ``AddressRandomization`` is set to ``once``, MAC address is
       randomized a single time when **iwd** starts or when the hardware is
       detected for the first time (due to hotplug, etc.)

       If ``AddressRandomization`` is set to ``network``, the MAC address is
       randomized on each connection to a network. The MAC is generated based on
       the SSID and permanent address of the adapter. This allows the same MAC
       to be generated each time connecting to a given SSID while still hiding
       the permanent address.

   * - AddressRandomizationRange
     - Values: **full**, nic

       One can control which part of the address is randomized using this
       setting.

       When using ``AddressRandomizationRange`` set to ``nic``, only the NIC
       specific octets (last 3 octets) are randomized.  Note that the
       randomization range is limited to 00:00:01 to 00:00:FE.  The permanent
       mac address of the card is used for the initial 3 octets.

       When using ``AddressRandomizationRange`` set to ``full``, all 6 octets
       of the address are randomized.  The locally-administered bit will be
       set.

   * - RoamThreshold
     - Value: rssi dBm value, from -100 to 1, default: **-70**

       This can be used to control how aggressively **iwd** roams.

   * - ManagementFrameProtection
     - Values: 0, **1** or 2

       When ``ManagementFrameProtection`` is ``0``, MFP is completely turned
       off, even if the hardware is capable.  This setting is not recommended.

       When ``ManagementFrameProtection`` is ``1``, MFP is enabled if the local
       hardware and remote AP both support it.

       When ``ManagementFrameProtection`` is ``2``, MFP is always required.
       This can prevent successful connection establishment on some hardware or
       to some networks.

   * - ControlPortOverNL80211
     - Values: false, **true**

       Enable/Disable sending EAPoL packets over NL80211.  Enabled by default
       if kernel support is available.  Doing so sends all EAPoL traffic over
       directly to the supplicant process (**iwd**) instead of putting these on
       the Ethernet device.  Since only the supplicant can usually make
       sense / decrypt these packets, enabling this option can save some CPU
       cycles on your system and avoids certain long-standing race conditions.

   * - DisableANQP
     - Values: false, **true**

       Enable/disable ANQP queries. The way IWD does ANQP queries is dependent
       on a recent kernel patch (available in Kernel 5.3). If your kernel does
       not have this functionality this should be disabled (default).  Some
       drivers also do a terrible job of sending public action frames
       (freezing or crashes) which is another reason why this has been turned
       off by default.  If you want to easily utilize Hotspot 2.0 networks,
       then setting ``DisableANQP`` to ``false`` is recommended.

Network
---------

The group ``[Network]`` contains network configuration related settings.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - NameResolvingService
     - Values: resolvconf, **systemd**

       Configures a DNS resolution method used by the system.

       This configuration option must be used in conjunction with
       ``EnableNetworkConfiguration`` and provides the choice of system
       resolver integration.

       If not specified, ``systemd`` is used as default.

   * - RoutePriorityOffset
     - Values: uint32 value (default: **300**)

       Configures a route priority offset used by the system to prioritize
       the default routes. The route with lower priority offset is preferred.

       If not specified, ``300`` is used as default.

Blacklist
---------

The group ``[Blacklist]`` contains settings related to blacklisting of BSSes.
If **iwd** determines that a connection to a BSS fails for a reason that
indicates the BSS is currently misbehaving or misconfigured (e.g. timeouts,
unexpected status/reason codes, etc), then **iwd** will blacklist this BSS
and avoid connecting to it for a period of time.  These options let the user
control how long a misbehaved BSS spends on the blacklist.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - InitialTimeout
     - Values: uint64 value in seconds (default: **60**)

       The initial time that a BSS spends on the blacklist.
   * - Multiplier
     - Values: unsigned int value in seconds (default: **30**)

       If the BSS was blacklisted previously and another connection attempt
       has failed after the initial timeout has expired, then the BSS blacklist
       time will be extended by a multiple of *Multiplier* for each
       unsuccessful attempt up to *MaxiumTimeout* time in seconds.
   * - MaximumTimeout
     - Values: uint64 value in seconds (default: **86400**)

       Maximum time that a BSS is blacklisted.

Rank
----

The group ``[Rank]`` contains settings related to ranking of networks for
autoconnect purposes.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - BandModifier5Ghz
     - Values: floating point value (default: **1.0**)

       Increase or decrease the preference for 5GHz access points by increasing
       or decreasing the value of this modifier.  5GHz networks are already
       preferred due to their increase throughput / data rate.  However, 5GHz
       networks are highly RSSI sensitive, so it is still possible for IWD to
       prefer 2.4Ghz APs in certain circumstances.

Scan
----

The group ``[Scan]`` contains settings related to scanning functionality.
No modification from defaults is normally required.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - DisablePeriodicScan
     - Values: true, **false**

       Disable periodic scan. Setting this option to 'true' will prevent
       **iwd** from issuing the periodic scans for the available networks while
       disconnected.  The behavior of the user-initiated scans isn't affected.
       The periodic scan is enabled by default.
   * - DisableRoamingScan
     - Values: true, **false**

       Disable roaming scan. Setting this option to 'true' will prevent **iwd**
       from trying to scan when roaming decisions are activated.  This can
       prevent **iwd** from roaming properly, but can be useful for networks
       operating under extremely low rssi levels where roaming isn't possible.

SEE ALSO
========

iwd(8), iwd.network(5)
