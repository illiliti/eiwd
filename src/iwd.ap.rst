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

General Settings
----------------

The group ``[General]`` contains general AP configuration.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - Channel
     - Channel number

       Optional channel number for the access point to operate on. If omitted
       the channel will be chosen automatically. Channels greater than or equal
       to 36 will select the 5GHz band for the AP to operate on.

       Note: Due to regulatory requirements the linux kernel does not allow or
       strictly limits 5GHz use in AP mode while in world roaming. These
       frequencies become available once the country is set, either via IWD's
       main.conf option ``[General].Country`` (see ``man iwd.config``) or
       externally (e.g. iw reg set <CC>). If you are having trouble using 5GHz
       ensure the country is set, and that the desired frequency/channel is
       unrestricted.

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

       WPA-PSK Passphrase to be used with this access point.  At least one of
       *Passphrase*, *PreSharedKey* must be present.

   * - PreSharedKey
     - 64-character hex-string

       Processed passphrase for this network in the form of a hex-encoded
       32-byte pre-shared key.  Either this or *Passphrase* must be present.

   * - PairwiseCiphers
     - Comma separated list of pairwise ciphers for the AP supports.

       Values can include: TKIP, CCMP, GCMP, GCMP-256, CCMP-256

       The underlying hardware and IWD's AP implementation must also support the
       ciphers listed

   * - GroupCipher
     - Group cipher the AP uses

       A single cipher value the AP can use as the group cipher. Values are the
       same as pairwise ciphers and the same restrictions apply (hardware and
       IWD implementation must support the cipher)

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
     - Local IP address or a comma-separated list of prefix-notation addresses

       Optional local address pool for the access point and the DHCP server.
       If a single address is provided this address will be set on the AP
       interface and any other DHCP server options will be derived from it
       if not overridden by other settings below.

       If a list of addresses and prefix lengths is specified (in the
       `<IP>/<prefix-len>` format), a single subnet address will be selected
       from the available space each time this profile is started.  The subnet
       size is based on the ``[IPv4].Netmask`` setting.

       If *Address* is not provided and no IP address is set on the
       interface prior to calling `StartProfile` the value of the main.conf
       ``[IPv4].APAddressPool`` setting will be inherited, which in turn
       defaults to 192.168.0.0/16.

       For example, if ``[IPv4].Netmask`` is set to 255.255.255.0 and this
       setting, or the global *APAddressPool* fallback, is set to
       ``192.168.0.0/16, 10.0.0.0/22``, IWD will select one of the 256 subnets
       with addresses in the 192.168.<0-255>.0/24 range or one of the 4 subnets
       with addresses in the 10.0.<0-3>.0/24 range, allowing 270 possible
       subnets.  Defining an address pool larger than the desired subnet gives
       IWD a chance to avoid conflicts if other interfaces on the system use
       dynamically assigned addresses.

   * - Gateway
     - IP Address of gateway

       IP address of the gateway to be advertised by DHCP. This will fall back
       to the local IP address if not provided.

   * - Netmask
     - Local netmask of the AP

       Defaults to a 28-bit netmask if not provided.

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

Wi-Fi Simple Configuration
--------------------------

The group ``[WSC]`` fine-tunes some Wi-Fi Simple Configuration local parameters
(formerly known as WPS, Wi-Fi Protected Setup.)

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - DeviceName
     - 1..32-character string

       Optional Device Name string for the AP to advertise as.  Defaults to
       the SSID.

   * - PrimaryDeviceType
     - Subcategory string or a 64-bit integer

       Optional Primary Device Type for the AP to advertise as.  Defaults to
       PC computer.  Can be specified as a lower-case WSC v2.0.5 subcategory
       string or a 64-bit integer encoding, from MSB to LSB: the 16-bit
       category ID, the 24-bit OUI, the 8-bit OUI type and the 16-bit
       subcategory ID.

   * - AuthorizedMACs
     - Comma-separated MAC address list

       Optional list of Authorized MAC addresses for the WSC registrar to
       check on association.  Each address is specified in the
       colon-hexadecimal notation.  Defaults to no MAC-based checks.

SEE ALSO
========

iwd(8), iwd.network(5)
