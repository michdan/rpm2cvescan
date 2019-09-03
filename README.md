rpm2cvescan
==============

# Original repo
- [bigHosting/rpm2cvescan](https://github.com/bigHosting/rpm2cvescan)


This python version is a rewrite of the original Perl version, as it needed
an extra C program to use the Python rpmvercmp function. It was more logical
to have the complete tool in Python.

As the tool needs to run on CentOS 6 and 7 systems (in my setup) it's written
and tested for python 2.7.5.


rpm2cvescan is an RedHat/CentOS 5/6/7/8 rpm cve vulnerability scanner based on
  * RedHat's OVAL infor for RHEL5,6,7,8:
    * com.redhat.rhsa-RHEL5.xml
    * com.redhat.rhsa-RHEL6.xml
    * com.redhat.rhsa-RHEL7.xml
    * com.redhat.rhsa-RHEL8.xml

How does this work?
  Based on the collected rpms, the rhel major release of the system it's run on
  and the corresponding rhsa file, a data structure is created to store all
  patches with the data that is used (RHA ID, CVEs, rpms + version)

  After collecting all data, a routine will walk trough all patches and per
  patch will check if any of the rpms is installed and when it's found, if
  the version of the rpm is the same or newer then the one mentioned in the
  patch.

  When all rpms of a patch are compared with the installed rpms, a decission
  is made based on the following criteria:

  * At least 1 rpm was found on the system and it's version is lower then
    reported with the patch
    -> added to 'to_install' patch list.

  * At least 1 rpm was found on the system and it's version is equal or
    higher then reported with the patch **and** no rpms were found of
    the 1st category
    -> added to added to 'installed' patch list.

  * No rpms were found that the patch applies to
    -> added to the 'na' patch list.

How to run the scanner:
  * download these files to be sure you have the latest revision:
       # ./download.sh

  * run the python program:
       # ./rpm2cvescan.py


This tool will only report information about packages used by RedHat. If custom rpms are used,
e.g. php 7.1 or httpd 2.4 , this tool is not capabale of detecting vulnerabilities simply
because com.redhat.rhsa-RHEL7.xml has info on what's installed by default on your distro version,
e.g. php 5.3 for EL6.

```
Output example:

RHAs that need to be installed on system:

RHSA-2017:0372
  CVE-2016-5195 - High - 7.8 (cvss3)
  CVE-2016-7039 - High - 7.5 (cvss3)
  CVE-2016-8666 - High - 7.5 (cvss3)
    kernel-headers 0:3.10.0-862.11.6.el7 < 0:4.5.0-15.2.1.el7
    kernel-tools 0:3.10.0-862.11.6.el7 < 0:4.5.0-15.2.1.el7
    kernel 0:3.10.0-862.11.6.el7 < 0:4.5.0-15.2.1.el7
    kernel-tools-libs 0:3.10.0-862.11.6.el7 < 0:4.5.0-15.2.1.el7
    python-perf 0:3.10.0-862.11.6.el7 < 0:4.5.0-15.2.1.el7

RHSA-2018:1453
  CVE-2018-1111 - High - 7.5 (cvss3)
    dhcp-common 12:4.2.5-68.el7.centos.1 < 12:4.2.5-68.el7_5.1
    dhclient 12:4.2.5-68.el7.centos.1 < 12:4.2.5-68.el7_5.1
    dhcp-libs 12:4.2.5-68.el7.centos.1 < 12:4.2.5-68.el7_5.1

[....]

RHAs that are installed on system:

RHSA-2014:0678
  CVE-2014-0196 - Medium - 6.9 (cvss2)
    kernel-headers 0:3.10.0-862.11.6.el7 => 0:3.10.0-123.1.2.el7
    kernel-tools 0:3.10.0-862.11.6.el7 => 0:3.10.0-123.1.2.el7
    kernel 0:3.10.0-862.11.6.el7 => 0:3.10.0-123.1.2.el7
    kernel-tools-libs 0:3.10.0-862.11.6.el7 => 0:3.10.0-123.1.2.el7
    python-perf 0:3.10.0-862.11.6.el7 => 0:3.10.0-123.1.2.el7

RHSA-2014:0679
  CVE-2010-5298 - Medium - 4.3 (cvss2)
  CVE-2014-0195 - Medium - 5.8 (cvss2)
  CVE-2014-0198 - Medium - 4.3 (cvss2)
  CVE-2014-0221 - Medium - 4.3 (cvss2)
  CVE-2014-0224 - Medium - 5.8 (cvss2)
  CVE-2014-3470 - Medium - 4.3 (cvss2)
    openssl 1:1.0.2k-12.el7 => 1:1.0.1e-34.el7_0.3
    openssl-libs 1:1.0.2k-12.el7 => 1:1.0.1e-34.el7_0.3

[....]

Not applicable RHAs for system:

RHSA-2014:0675
  CVE-2014-0429 - Medium - 6.8 (cvss2)
  CVE-2014-0446 - Medium - 6.8 (cvss2)
  CVE-2014-0451 - Medium - 6.8 (cvss2)
  CVE-2014-0452 - Medium - 6.8 (cvss2)
  CVE-2014-0453 - Medium - 4.0 (cvss2)
  CVE-2014-0454 - Medium - 6.8 (cvss2)
  CVE-2014-0455 - Medium - 6.8 (cvss2)
  CVE-2014-0456 - Medium - 6.8 (cvss2)
  CVE-2014-0457 - Medium - 6.8 (cvss2)
  CVE-2014-0458 - Medium - 6.8 (cvss2)
  CVE-2014-0459 - Medium - 4.3 (cvss2)
  CVE-2014-0460 - Medium - 5.8 (cvss2)
  CVE-2014-0461 - Medium - 6.8 (cvss2)
  CVE-2014-1876 - Low - 1.9 (cvss2)
  CVE-2014-2397 - Medium - 6.8 (cvss2)
  CVE-2014-2398 - Low - 2.6 (cvss2)
  CVE-2014-2402 - Medium - 6.8 (cvss2)
  CVE-2014-2403 - Medium - 5.0 (cvss2)
  CVE-2014-2412 - Medium - 6.8 (cvss2)
  CVE-2014-2413 - Medium - 4.3 (cvss2)
  CVE-2014-2414 - Medium - 6.8 (cvss2)
  CVE-2014-2421 - Medium - 6.8 (cvss2)
  CVE-2014-2423 - Medium - 6.8 (cvss2)
  CVE-2014-2427 - Medium - 6.8 (cvss2)

RHSA-2014:0680
  CVE-2014-0224 - Medium - 5.8 (cvss2)

[....]

```
TODO:

  * Add argument support to limit output to 1 of the 3 categories

  * Add totals

