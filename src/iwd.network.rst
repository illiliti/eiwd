=============
 iwd.network
=============

-----------------------------------------
Network configuration for wireless daemon
-----------------------------------------

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

Network configuration files ``.open``, ``.psk`` and ``.8021x``

DESCRIPTION
===========

**iwd** stores information on known networks, and reads information on
pre-provisioned networks, from small text configuration files.  Those files
live in the state directory specified by the environment variable
*$STATE_DIRECTORY*, which is normally provided by **systemd**.  In the absence
of such an environment variable it defaults to *$LIBDIR/iwd*, which normally
is set to */var/lib/iwd*.  You can create, modify or remove those files.
**iwd** monitors the directory for changes and will update its state
accordingly.  **iwd** will also modify these files in the course of network
connections or as a result of D-Bus API invocations.

FILE FORMAT
===========

The syntax is similar to that of GNOME keyfile syntax (which is based on the
format defined in the Desktop Entry Specification, see
*http://freedesktop.org/Standards/desktop-entry-spec*).  The recognized groups
as well as keys and values in each group are documented here.  Defaults are
written in bold.

For completeness we include the description of the file syntax here. This is
the syntax that the ell library's l_settings class implements. The syntax is
based on lines and lines are delimited by newline characters.

Empty lines are ignored and whitespace at the beginning of a line is ignored.
Comment lines have ``#`` as their first non-whitespace character.

Key-value lines contain a setting key, an equal sign and the value of the
setting.  Whitespace preceding the key, the equal sign or the value, is
ignored.  The key must be a continuous string of alphanumeric and underscore
characters and minus signs only.  The value starts at the first non-whitespace
character after the first equal sign on the line and ends at the end of the
line and must be correctly UTF-8-encoded. A boolean value can be ``true`` or
``false`` but ``0`` or ``1`` are also allowed.  Integer values are written
in base 10.  String values, including file paths and hexstrings, are written
as is except for five characters that may be backslash-escaped: space,
``\t``, ``\r``, ``\n`` and backslash itself.  The latter three must be
escaped.  A space character must be escaped if it is the first character
in the value string and is written as ``\s``.

Settings are interpreted depending on the group they are in.  A group starts
with a group header line and contains all settings until the next group's
header line.  A group header line contains a ``[`` character followed by
the group name and a ``]`` character.  Whitespace is allowed before the
``[`` and after the ``]``.  A group name consists of printable characters
other than ``[`` and ``]``.

If a group name starts with the ``@`` sign, that group's content is handled
by a parser extension instead and does not cause the previous non-extension
group to end.  The initial ``@`` sign must be followed by a non-empty
extension name, another ``@`` sign and a group name as defined above. The
extension name consists of printable characters other than ``@``. No
whitespace is allowed after the group header in this case.  The extension
payload syntax and length are determined by the extension name.  Normal
parsing rules defined in this section resume at the end of the payload and
any settings after the end of the payload are handled as part of the previous
non-extension group.

Currently the only extension supported is named pem and allows embedding the
contents of a single RFC7468 PEM-formatted payload or a sequence of multiple
PEM payloads.  The payload should start with the ``-----BEGIN`` string on a
line following the group header line and end with an ``-----END`` line as
specified in the RFC.  Newline characters before, between and after PEM
payloads are included in the extension payload.  No other extra characters
are allowed.

NAMING
======

File names are based on the network's SSID and security type: Open,
PSK-protected or 802.1x. The name consist of the encoding of the SSID
followed by ``.open``, ``.psk`` or ``.8021x``.  The SSID appears verbatim
in the name if it contains only alphanumeric characters, spaces, underscores
or minus signs.  Otherwise it is encoded as an equal sign followed by the
lower-case hex encoding of the name.

SETTINGS
========

The settings below are split into several sections and grouped into broad
categories.  Each category has a group associated with it which is given at
the beginning of each sub-section.  Recognized keys and valid values are listed
following the group definition.

General Settings
----------------

The group ``[Settings]`` contains general settings.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - AutoConnect
     - Values: **true**, false

       Whether the network can be connected to automatically
   * - Hidden
     - Values: true, **false**

       Whether the network is hidden, i.e. its SSID must be included in an
       active scan request
   * - AlwaysRandomizeAddress
     - Values: true, **false**

       If enabled, the MAC address will be fully randomized on each connection.
       This option is only used if [General].AddressRandomization is set to
       'network'. See iwd.config. This setting should not be used with
       [Settings].AddressOverride, if both are set AddressOverride will be used.
   * - AddressOverride
     - MAC address string

       Override the MAC address used for connecting to this network. This option
       is only used if [General].AddressRandomization is set to 'network'. See
       iwd.config. This setting should not be used with
       [Settings].AlwaysRandomizeAddress, if both are set AddressOverride will
       be used.
   * - TransitionDisable
     - Values: true, **false**

       If enabled, the use of TKIP pairwise cipher and connections without
       Management Frame Protection are disallowed.  This will make certain
       legacy access points unavailable for use.  Additional security hardening
       can also be applied via the [Settings].DisabledTransitionModes setting.

       Properly configured Access Points will typically update this setting
       appropriately via Transition Disable indications.  User customization
       of this value is thus typically not required.
   * - DisabledTransitionModes
     - Comma-separated list of disabled transition modes:

       * personal
       * enterprise
       * open

       If 'personal' mode is disabled, then legacy WPA2-Personal access points
       are no longer available to be connected to or roamed to.  Only access
       points utilizing WPA3-Personal will be considered.

       If 'enterprise' mode is disabled, then legacy WPA2-Enterprise access
       points are no longer available to be connected to or roamed to.

       If 'open' mode is disabled, then non-OWE enabled access points will
       not be connected to.

       Properly configured Access Points will typically update this setting
       appropriately via Transition Disable indications.  User customization
       of this value is thus typically not required.
   * - UseDefaultEccGroup
     - Values: true, false

       Forces the use of the default ECC group (19) for protocols using ECC
       (WPA3 and OWE) if set true. If unset IWD will learn the capabilities of
       the network based on its initial association and retain that setting for
       the duration of its process lifetime.

Network Authentication Settings
-------------------------------

The group ``[Security]`` contains settings for Wi-Fi security and
authentication configuration. This group can be encrypted by enabling
``SystemdEncrypt``, see *iwd.config* for details on this option. If this
section is encrypted (only contains EncryptedSalt/EncryptedSecurity) it should
not be modified. Modifying these values will result in the inability to
connect to that network.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - Passphrase
     - 8..63 character string

       Passphrase to be used when connecting to WPA-Personal networks.
       Required when connecting to WPA3-Personal (SAE) networks.  Also
       required if the *PreSharedKey* is not provided.  If not provided in
       settings, the agent will be asked for the passphrase at connection
       time.
   * - PasswordIdentifier
     - string

       An identifer string to be used with the passphrase. This is used for
       WPA3-Personal (SAE) networks if the security has enabled password
       identifiers for clients.
   * - PreSharedKey
     - 64 character hex string

       Processed passphrase for this network in the form of a hex-encoded 32
       byte pre-shared key.  Must be provided if *Passphrase* is omitted.
   * - EAP-Method
     - one of the following methods:

       AKA, AKA', MSCHAPV2, PEAP, PWD, SIM, TLS, TTLS.

       The following additional methods are allowed as TTLS/PEAP inner
       methods:

       GTC, MD5.
   * - EAP-Identity
     - string

       Identity string transmitted in plaintext.  Depending on the EAP method,
       this value can be optional or mandatory.  GTC, MD5, MSCHAPV2, PWD
       require an identity, so if not provided, the agent will be asked for it
       at connection time.  TLS based methods (PEAP, TLS, TTLS) might still
       require an *EAP-Identity* to be set, depending on the RADIUS server
       configuration.
   * - EAP-Password
     - string

       Password to be provided for WPA-Enterprise authentication.  If not
       provided, the agent will be asked for the password at connection time.
       Required by: GTC, MD5, MSCHAPV2, PWD.
   * - EAP-Password-Hash
     - hex string

       Some EAP methods can accept a pre-hashed version of the password.  For
       MSCHAPV2, a MD4 hash of the password can be given here.
   * - | EAP-TLS-CACert,
       | EAP-TTLS-CACert,
       | EAP-PEAP-CACert
     - absolute file path or embedded pem

       Path to a PEM-formatted X.509 root certificate list to use for trust
       verification of the authenticator.  The authenticator's server's
       certificate chain must be verified by at least one CA in the list for
       the authentication to succeed.  If omitted, then authenticator's
       certificate chain will not be verified (not recommended.)
   * - EAP-TLS-ClientCert
     - absolute file path or embedded pem

       Path to the client X.509 certificate or certificate chain to send on
       server request.
   * - EAP-TLS-ClientKey
     - absolute file path or embedded pem

       Path to the client private key corresponding to the public key provided
       in *EAP-TLS-ClientCert*.  The recommended format is PKCS#8 PEM.
   * - EAP-TLS-ClientKeyBundle
     - absolute file path

       As an alternative to *EAP-TLS-ClientCert* and *EAP-TLS-ClientKey* IWD
       can load both the certificate and the private key from a container file
       pointed by this setting.  The recommended format is PKCS#12 when this
       is used.
   * - | EAP-TLS-
       | ClientKeyPassphrase
     - string

       Decryption key for the client key files.  This should be used if the
       certificate or the private key in the files mentioned above is encrypted.
       When not given, the agent is asked for the passphrase at connection time.
   * - | EAP-TLS-ServerDomainMask,
       | EAP-TTLS-ServerDomainMask,
       | EAP-PEAP-ServerDomainMask
     - string

       A mask for the domain names contained in the server's certificate. At
       least one of the domain names present in the certificate's Subject
       Alternative Name extension's DNS Name fields or the Common Name has to
       match at least one mask, or authentication will fail.  Multiple masks
       can be given separated by semicolons.  The masks are split into segments
       at the dots.  Each segment has to match its corresponding label in the
       domain name. An asterisk segment in the mask matches any label.  An
       asterisk segment at the beginning of the mask matches one or more
       consecutive labels from the beginning of the domain string.
   * - | EAP-TLS-FastReauthentication,
       | EAP-TTLS-FastReauthentication,
       | EAP-PEAP-FastReauthentication,
     - Values: **true**, false

       Controls whether TLS session caching for EAP-TLS, EAP-TTLS and EAP-PEAP
       is used.  This allows for faster re-connections to EAP-Enterprise based
       networks.

       Some network authenticators may be misconfigured in a way that TLS
       session resumption is allowed but actually attempting it will cause
       the EAP method to fail or time out.  In that case, assuming the
       credentials and other settings are correct, every other connection
       attempt will fail as sessions are cached and forgotten in alternating
       attempts.  Use this setting to disable caching for this network.
   * - | EAP-TTLS-Phase2-Method
     - | The following values are allowed:
       |    Tunneled-CHAP,
       |    Tunneled-MSCHAP,
       |    Tunneled-MSCHAPv2,
       |    Tunneled-PAP or
       |    a valid EAP method name (see *EAP-Method*)

       Phase 2 authentication method for EAP-TTLS.  Can be either one of the
       TTLS-specific non-EAP methods (Tunneled-\*), or any EAP method
       documented here.  The following two settings are used if any of the
       non-EAP methods is used.
   * - | EAP-TTLS-Phase2-Identity
     - The secure identity/username string for the TTLS non-EAP Phase 2
       methods.  If not provided **iwd** will request a username at connection
       time.
   * - | EAP-TTLS-Phase2-Password
     - Password string for the TTLS non-EAP Phase 2 methods. If not provided
       IWD will request a passphrase at connection time.
   * - EAP-TTLS-Phase2-*
     - Any settings to be used for the inner EAP method if one was specified
       as *EAP-TTLS-Phase2-Method*, rather than a TTLS-specific method. The
       prefix *EAP-TTLS-Phase2-* replaces the *EAP-* prefix in the setting
       keys and their usage is unchanged.  Since the inner method's
       negotiation is encrypted, a secure identity string can be provided.
   * - EAP-PEAP-Phase2-*
     - Any settings to be used for the inner EAP method with EAP-PEAP as the
       outer method. The prefix *EAP-PEAP-Phase2-* replaces the *EAP-* prefix
       in the setting keys and their usage is unchanged. Since the inner
       method's negotiation is encrypted, a secure identity string can be
       provided.

Network Configuration Settings
------------------------------

The group ``[Network]`` contains general network settings and any network
specific overrides for global defaults defined in the main iwd configuration
file.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - MulticastDNS
     - Values: true, false, resolve

       Configures multicast DNS for this network. If not specified,
       systemd-resolved's default value will remain untouched.
       See ``man 5 systemd.network`` for details.

       Only applies when ``NameResolvingService=systemd``.

The group ``[IPv4]`` contains settings for Internet Protocol version 4 (IPv4)
network configuration with the static addresses.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - Address
     - IPv4 address string

       The IPv4 address to assign. This field is `required` for the static
       configuration.
   * - Gateway
     - IPv4 address string

       The IPv4 address of the gateway (router). This field is `required` for
       the static configuration.
   * - DNS
     - IPv4 address string list, space delimited

       The IPv4 address(es) of the Domain Name System (DNS). This field is
       `optional`. DNS setting can be used to override the DNS entries received
       from the DHCP server.
   * - Netmask
     - IPv4 address string

       The IPv4 address of the subnet. This field is `optional`. 255.255.255.0
       is used as default Netmask.
   * - Broadcast
     - IPv4 address string

       The IPv4 address to be used for the broadcast. This field is `optional`.
   * - DomainName
     - string

       The DomainName is the name of the local Internet domain. This field is
       `optional`. DomainName setting can be used to override the DomainName
       value obtained from the DHCP server.

   * - SendHostname
     - Values: true, **false**

       Configures DHCP to include the hostname in the request. This setting
       is disabled by default.

The group ``[IPv6]`` contains settings for Internet Protocol version 6 (IPv6)
network configuration.

.. list-table::
   :header-rows: 0
   :stub-columns: 0
   :widths: 20 80
   :align: left

   * - Enabled
     - Boolean

       Whether IPv6 is enabled for this network.  If not provided, then the
       global default provided by [Network].EnableIPv6 setting will be used.
       If IPv6 is disabled, then the 'disable_ipv6' setting in sysfs will be
       set to 1 and no IPv6 addresses or routes will be created for this
       network.
   * - Address
     - IPv6 address string

       The IPv6 address to assign. This field is `required` for the static
       configuration.  The recognized format is according to inet_pton
       followed by '/' and prefix length.  If prefix length is omitted, then
       128 is assumed.
   * - Gateway
     - IPv6 address string

       The IPv6 address of the gateway (router). This field is `required` for
       the static configuration.
   * - DNS
     - IPv6 address string list, space delimited

       The IPv6 address(es) of the Domain Name System (DNS). This field is
       `optional`. DNS setting can be used to override the DNS entries received
       from the DHCPv6 server or via Router Advertisements.
   * - DomainName
     - string

       The DomainName is the name of the local Internet domain. This field is
       `optional`. DomainName setting can be used to override the DomainName
       value obtained from the DHCPv6 server or via Router Advertisements.


Embedded PEMs
-------------

Rather than including an absolute path to a PEM file (for certificates and
keys), the PEM itself can be included inside the settings file and referenced
directly. This allows IEEE 802.1x network provisioning using a single file
without any references to certificates or keys on the system.

An embedded PEM can appear anywhere in the settings file using the following
format (in this example the PEM is named 'my_ca_cert'):

.. code-block::

  [@pem@my_ca_cert]
  ----- BEGIN CERTIFICATE -----
  <PEM data>
  ----- END CERTIFICATE -----

After this special group tag it's as simple as pasting in a PEM file including
the BEGIN/END tags. Now 'my_ca_cert' can be used to reference the certificate
elsewhere in the settings file by prefixing the value with 'embed:'

EAP-TLS-CACert=embed:my_ca_cert

This is not limited to CA Certificates either. Client certificates, client keys
(encrypted or not), and certificate chains can be included.

EXAMPLES
========

The following are some examples of common configurations

Open Network (Hidden)
---------------------

.. code-block::

   [Settings]
   Hidden=true

Pre-Shared Key (PSK)
--------------------

.. code-block::

   [Security]
   Passphrase=secret123

PWD
---

.. code-block::

   [Security]
   EAP-Method=PWD
   EAP-Identity=user@domain.com
   EAP-Password=secret123

TLS
---

.. code-block::

   [Security]
   EAP-Method=TLS
   EAP-TLS-ClientCert=/certs/client-cert.pem
   EAP-TLS-ClientKey=/certs/client-key.pem
   EAP-TLS-CACert=/certs/ca-cert.pem
   EAP-TLS-ServerDomainMask=*.domain.com

TTLS + PAP
----------

.. code-block::

   [Security]
   EAP-Method=TTLS
   EAP-Identity=open@identity.com
   EAP-TTLS-CACert=/certs/ca-cert.pem
   EAP-TTLS-Phase2-Method=Tunneled-PAP
   EAP-TTLS-Phase2-Identity=username
   EAP-TTLS-Phase2-Password=password
   EAP-TTLS-ServerDomainMask=*.domain.com

PEAP + MSCHAPv2
---------------

.. code-block::

   [Security]
   EAP-Method=PEAP
   EAP-Identity=open@identity.com
   EAP-PEAP-CACert=/certs/ca-cert.pem
   EAP-PEAP-Phase2-Method=MSCHAPV2
   EAP-PEAP-Phase2-Identity=username
   EAP-PEAP-Phase2-Password=password
   EAP-PEAP-ServerDomainMask=*.domain.com

SEE ALSO
========

iwd(8), iwd.config(5)
