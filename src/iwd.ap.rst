============
 iwd.ap
============

--------------------------------------
Configuration of IWD access points
--------------------------------------

:Author: James Prestwood <prestwoj@gmail.com>
:Copyright: 2020 Intel Corporation
:Version: iwd
:Date: 20 October 2020
:Manual section: 5
:Manual group: Linux Connectivity

NAME
====
iwd.ap - Access point provisioning files

SYNOPSIS
========

Description of access point provisioning files.

DESCRIPTION
===========

An access point provisioning file defines the configuration of an IWD access
point. These files live in *$STATE_DIRECTORY*/ap (/var/lib/iwd/ap by default).
They are read when the `net.connman.iwd.AccessPoint.StartProfile(ssid)` DBus
method is used.

FILE FORMAT
===========

See *iwd.network* for details on the settings file syntax.

SETTINGS
========

The settings are split into several categories.  Each category has a group
associated with it and is described in the corresponding table below.

Network Authentication Settings
-------------------------------

The group ``[Security]`` contains settings for Wi-Fi security and authentication
configuration.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - Passphrase
     - 8..63 character string

       WPA-PSK Passphrase to be used with this access point.

IPv4 Network Configuration
--------------------------

The group ``[IPv4]`` contains settings for IWD's built-in DHCP server.  All
settings are optional.  They're used if network configuration was enabled as
described in ``iwd.config(5)``.  Omitting the ``[IPv4]`` group disables
network configuration for this access point so if an all-defaults DHCP setup
is desired, the group header line must still be present:

.. code-block::

   # Enable network configuration
   [IPv4]

   [other groups follow]

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80

   * - Address
     - Local IP address

       Optional local address pool for the access point and the DHCP server.
       If provided this addresss will be set on the AP interface and any other
       DHCP server options will be derived from it, unless they are overridden
       by other settings below.  If *Address* is not provided and no IP
       address is set on the interface prior to calling `StartProfile`,  the IP
       pool defined by the global ``[General].APRanges`` setting will be used.

   * - Gateway
     - IP Address of gateway

       IP address of the gateway to be advertised by DHCP. This will fall back
       to the local IP address if not provided.

   * - Netmask
     - Local netmask of the AP

       This will be generated from ``[IPv4].Address`` if not provided.

   * - DNSList
     - List of DNS servers as a comma-separated IP address list

       A list of DNS servers which will be advertised by the DHCP server. If
       not provided no DNS servers will be sent by the DHCP server.

   * - LeaseTime
     - Time limit for DHCP leases in seconds

       Override the default lease time.

   * - IPRange
     - Range of IPs given as two addresses separated by a comma

       From and to addresses of the range assigned to clients through DHCP.
       If not provided the range from local address + 1 to .254 will be used.

SEE ALSO
========

iwd(8), iwd.network(5)
