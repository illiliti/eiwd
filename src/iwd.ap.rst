============
 iwd.ap
============

--------------------------------------
Configuration of IWD access point
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

An access point provisioning files define the configuration of an IWD access
point. These files live in *$STATE_DIRECTORY*/ap (/var/lib/iwd/ap by default).

FILE FORMAT
===========

See *iwd.network* for details on the file format.

SETTINGS
========

The settings are split into several categories.  Each category has a group
associated with it and described in separate tables below.

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

       Passphrase to be used with this access point.

DHCP Server Settings
--------------------

The group ``[IPv4]`` contains settings for IWD's built in DHCP server. All
settings are optional.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80

   * - Address
     - IP Address of AP

       Optional address for the DHCP server/access point. If provided this
       address will be set on the AP interface and any other DHCP server options
       will be derived from this address, unless they are overriden inside the
       AP profile. If [IPv4].Address is not provided and no IP address is set
       on the interface prior to calling StartProfile the IP pool will be used.

   * - Gateway
     - IP Address of gateway

       IP address of gateway. This will inherit from [IPv4].Address if not
       provided.

   * - Netmask
     - Netmask of DHCP server

       This will be generated from [IPv4].Address if not provided.

   * - DNSList
     - List of DNS servers

       A list of DNS servers which will be advertised by the DHCP server. If
       not provided no DNS servers will be sent by the DHCP server.

   * - LeaseTime
     - Time limit for DHCP leases

       Override the default lease time.

   * - IPRange
     - Range of IPs to use for the DHCP server

       If not provided a default range will be chosen which is the DHCP server
       address + 1 to 254.

SEE ALSO
========

iwd(8), iwd.network(5)
