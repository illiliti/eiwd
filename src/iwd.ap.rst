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

SEE ALSO
========

iwd(8), iwd.network(5)
