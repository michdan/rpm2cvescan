#!/usr/bin/python
import rpm
import subprocess
import xml.etree.ElementTree as ET

namespace='{http://oval.mitre.org/XMLSchema/oval-definitions-5}'
patchlist = {}
patchstatus = {}
rpmlist = []
rhelversions = ['RHEL5', 'RHEL6', 'RHEL7', 'RHEL8' ]
base_patchfilename='./com.redhat.rhsa-'

rhel_version=subprocess.check_output('cat /etc/redhat-release',shell = True).split()[3]
rhel_major=rhel_version.split('.')[0]

hostname=subprocess.check_output('hostname',shell = True).strip()

# =======================================================================
# Monkey patch ElementTree
#
# Function to import xml in the order it's stored in the xml
# instead of just random dump items in dict
def _serialize_xml(write, elem, encoding, qnames, namespaces):
    tag = elem.tag
    text = elem.text
    if tag is ET.Comment:
        write("<!--%s-->" % ET._encode(text, encoding))
    elif tag is ET.ProcessingInstruction:
        write("<?%s?>" % ET._encode(text, encoding))
    else:
        tag = qnames[tag]
        if tag is None:
            if text:
                write(ET._escape_cdata(text, encoding))
            for e in elem:
                _serialize_xml(write, e, encoding, qnames, None)
        else:
            write("<" + tag)
            items = elem.items()
            if items or namespaces:
                if namespaces:
                    for v, k in sorted(namespaces.items(),
                                       key=lambda x: x[1]):  # sort on prefix
                        if k:
                            k = ":" + k
                        write(" xmlns%s=\"%s\"" % (
                            k.encode(encoding),
                            ET._escape_attrib(v, encoding)
                            ))
                #for k, v in sorted(items):  # lexical order
                for k, v in items: # Monkey patch
                    if isinstance(k, ET.QName):
                        k = k.text
                    if isinstance(v, ET.QName):
                        v = qnames[v.text]
                    else:
                        v = ET._escape_attrib(v, encoding)
                    write(" %s=\"%s\"" % (qnames[k], v))
            if text or len(elem):
                write(">")
                if text:
                    write(ET._escape_cdata(text, encoding))
                for e in elem:
                    _serialize_xml(write, e, encoding, qnames, None)
                write("</" + tag + ">")
            else:
                write(" />")
    if elem.tail:
        write(ET._escape_cdata(elem.tail, encoding))

ET._serialize_xml = _serialize_xml

from collections import OrderedDict

class OrderedXMLTreeBuilder(ET.XMLTreeBuilder):
    def _start_list(self, tag, attrib_in):
        fixname = self._fixname
        tag = fixname(tag)
        attrib = OrderedDict()
        if attrib_in:
            for i in range(0, len(attrib_in), 2):
                attrib[fixname(attrib_in[i])] = self._fixtext(attrib_in[i+1])
        return self._target.start(tag, attrib)

# =======================================================================


# =======================================================================
# Class my_rpm
#
# Created to easily store rpm info and compare rpm versions
# =======================================================================
class my_rpm:
    def __init__(self, name_string):
	if ':' in name_string:
           self.name = name_string.split(':')[0].rsplit('-',1)[0]
        else:
           self.name = name_string.split('.')[0].rsplit('-',1)[0]

        self.version_string = name_string[len(self.name)+1:]

        if 'el' in self.version_string:
           self.rhversion = self.version_string.split('el')[1].split('.')[0]
        else:
           self.rhversion = 0

    def __eq__(self, other):
        """Override the default Equals behavior"""
        if isinstance(other, self.__class__):
           if self.name == other.name:
              result = rpm.labelCompare((self.epoch(), self.version(), self.release()), (other.epoch(), other.version(), other.release()))
              if result == 0:
                 return True
              else:
                 return False
           else:
              return False
        else:
           return NotImplemented

    def __ne__(self, other):
        """Override the default Not Equal behavior"""
        if isinstance(other, self.__class__):
           if self.name == other.name:
              result = rpm.labelCompare((self.epoch(), self.version(), self.release()), (other.epoch(), other.version(), other.release()))
              if result == 0:
                 return False
              else:
                 return True
           else:
              return True
        else:
           return NotImplemented

    def __ge__(self, other):
        """Override the default Greater or equal behavior"""
        if isinstance(other, self.__class__):
           if self.name == other.name:
              result = rpm.labelCompare((self.epoch(), self.version(), self.release()), (other.epoch(), other.version(), other.release()))
              if result >= 0:
                 return True
              else:
                 return False
           else:
              return False
        else:
           return NotImplemented

    def epoch(self):
        if ':' in self.version_string:
           return self.version_string.split(':')[0]
        else:
           return 0

    def version(self):
        if ':' in self.version_string:
           ver_string = self.version_string.split(':')[1]
        else:
           ver_string = self.version_string
        return ver_string.split('-')[0]

    def release(self):
	if 'centos' in self.version_string:
           return self.version_string.split('-')[1].split('.centos')[0]
        else:
           return self.version_string.split('-')[1]

# =======================================================================

class my_patch:
    def __init__(self, name, version):
        self.name = name
        self.version = int(version)
        self.rhalist = []
        self.cvelist = []
        self.rpmlist = []

# =======================================================================
# Class my_cve
#
# Created to easily store cve info
# =======================================================================
class my_cve:
    def __init__(self, name, cvss, score):
        self.name = name
        self.cvss = int(cvss)
        self.score = float(score)

    #@classmethod
    def rating(self):
        if self.cvss == 3:
           if self.score > 8.9:
              severity = 'Critical'
           elif self.score > 6.9:
              severity = 'High'
           elif self.score > 3.9:
              severity = 'Medium'
           elif self.score > 0:
              severity = 'Low'
           else:
              severity = 'None'
        elif self.cvss == 2:
           if self.score > 6.9:
              severity = 'High'
           elif self.score > 3.9:
              severity = 'Medium'
           else:
              severity = 'Low'
        elif self.cvss == 1:
           if self.score > 8.9:
              severity = 'Critical'
           elif self.score > 6.9:
              severity = 'Important'
           elif self.score > 3.9:
              severity = 'Moderate'
           elif self.score > 0:
              severity = 'Low'
           elif self.score == 0:
              severity = 'None'
           else:
              severity = 'Unspecified'
        else:
           severity = 'Unknown'

        return severity

# =======================================================================


# =======================================================================
# Recursive criteria processing
#
# This is needed as RH CVE xml file is inconsistent with the amount
# of levels it uses for patch criteria
# =======================================================================
def recurse_criteria(my_criterion):
    my_rpmlist = []

    if my_criterion.tag == namespace+'criteria':
       for my_criteria in my_criterion:
           my_rpmlist += recurse_criteria(my_criteria)
    elif my_criterion.tag == namespace+'criterion':
       if 'is earlier than' in my_criterion.attrib['comment']:
          comment = my_criterion.attrib['comment'].split()
          rpmname_version = comment[0]+'-'+comment[-1]
          my_rpmlist.append(my_rpm(rpmname_version))

    return my_rpmlist

# =======================================================================

# get_patchlist
def get_patchlist(my_rhelversion):
    
    my_filename = base_patchfilename+my_rhelversion+'.xml'
    xml_tree = ET.parse(my_filename)

    my_patchlist = []
    #print xml_tree

    oval_definitions = xml_tree.getroot()
    for oval_subset in oval_definitions:
        #print (oval_subset.tag, "->", oval_subset.__dict__)

        if oval_subset.tag == namespace+'definitions':
           for oval_definition in oval_subset:

               #print oval_definition.tag, "-> ", oval_definition.__dict__
               patch_definition = oval_definition.attrib

               this_patch = my_patch(patch_definition['id'].split(':')[-1], patch_definition['version'])

               for patch_data in oval_definition:
                   #print patch_data.tag, "-> ", patch_data.__dict__
                   # Get CVE ID
                   if patch_data.tag == namespace+'metadata':
                      for metadata_data in patch_data:
                          if metadata_data.tag.endswith('reference'):
                             #print ""
                             #print metadata.__dict__
                             #print ""
                             if metadata_data.attrib['source'] != 'CVE':
                                this_patch.rhalist.append(metadata_data.attrib['ref_id'])

                      # get CVSS score of the CVE with this patch
                      if metadata_data.tag == namespace+'advisory':
                         for advisory_data in metadata_data:
                             # Assumption: CVSS3 score takes president over CVSS2
                             if advisory_data.tag == namespace+'cve':
                                if 'cvss3' in advisory_data.keys():
                                   cve = advisory_data.attrib['href'].split('/')[-1]
                                   score_txt = advisory_data.attrib['cvss3'].split('/')[0]
                                   score = float(score_txt)

                                   this_patch.cvelist.append(my_cve(cve, 3, score))

                                elif 'cvss2' in advisory_data.keys():
                                   cve = advisory_data.attrib['href'].split('/')[-1]
                                   score_txt = advisory_data.attrib['cvss2'].split('/')[0]
                                   score = float(score_txt)

                                   this_patch.cvelist.append(my_cve(cve, 2, score))
                                else:
                                   cve = advisory_data.attrib['href'].split('/')[-1]
                                   if 'impact' in advisory_data.keys():
                                      if advisory_data.attrib['impact'] == 'critical':
                                         score = 9.9
                                      elif advisory_data.attrib['impact'] == 'important':
                                         score = 8.9
                                      elif advisory_data.attrib['impact'] == 'moderate':
                                         score = 6.9
                                      elif advisory_data.attrib['impact'] == 'low':
                                         score = 3.9
                                      else:
                                         score = 0.0
                                   else:
                                      score = -0.1
                                   this_patch.cvelist.append(my_cve(cve, 1, score))

                   # Weed trough criteria.
                   # At 1st level we always have criteria
                   # At 2nd and later levels it is possible to find a criterion
                   # with package name and version we need to store
                   if patch_data.tag == namespace+'criteria':
                      for criteria2 in patch_data:
                          this_patch.rpmlist += recurse_criteria(criteria2)

               my_patchlist.append(this_patch)
               del this_patch

    return my_patchlist

# =======================================================================

# =======================================================================
# print_patchlist
def print_patchlist(my_patchlist):
    
    for patch in my_patchlist:
        print patch.name, patch.version

        for rha in patch.rhalist:
            print '  {}'.format(rha)

        for cve in patch.cvelist:
            print ' ', cve.name, \
                  '-', cve.rating(),
            if cve.cvss > 1:
               print '-', cve.score, '(cvss{})'.format(cve.cvss)
            else:
               print ''

        for rpm in patch.rpmlist:
            print '   ', rpm.name, \
                  '<', rpm.version_string,
            if rpm.rhversion > 0:
               print '({})'.format(rpm.rhversion)
            else:
               print ''

        print ''
# =======================================================================

# =======================================================================
# check_patchlist
def check_patchlist(my_patchlist, my_system_rpmlist):
    
    my_patches = {}
    my_patches['to_install'] = {}
    my_patches['installed'] = {}
    my_patches['na'] = {}

    for patch in my_patchlist:
        #print patch.name, patch.version
        rha = float(patch.name+'.'+str(patch.version))

        my_patch = {}
        my_patch['patch'] = patch
        my_patch['patched_rpms'] = []
        my_patch['unpatched_rpms'] = []
        my_patch['na_rpms'] = []

        patched_rpms=0
        unpatched_rpms=0

        for patch_rpm in patch.rpmlist:
            for system_rpm in my_system_rpmlist:
                if patch_rpm.name == system_rpm.name:
                   if patch_rpm.rhversion[0] == system_rpm.rhversion[0]:

	              if system_rpm >= patch_rpm:
                         my_patch['patched_rpms'].append(system_rpm)
                      else:
                         my_patch['unpatched_rpms'].append(system_rpm)
                   else:
                      my_patch['na_rpms'].append(system_rpm)

        if my_patch['unpatched_rpms']:
           my_patches['to_install'][rha] = my_patch
        elif my_patch['patched_rpms']:
           my_patches['installed'][rha] = my_patch
        else:
           my_patches['na'][rha] = my_patch

    return my_patches

def print_patchstatus(my_patchstatus):

    print 'RHAs that need to be installed on {}:'.format(hostname)
    print ''
    for to_key in sorted(my_patchstatus['to_install']):
        # RHA ID
        print my_patchstatus['to_install'][to_key]['patch'].rhalist[0]

        # Linked CVEs
        for cve in my_patchstatus['to_install'][to_key]['patch'].cvelist:
            print ' ', cve.name, \
                  '-', cve.rating(),
            if cve.cvss > 1:
               print '-', cve.score, '(cvss{})'.format(cve.cvss)
            else:
               print ''

        # Found unpatched rpms
        for system_rpm in sorted(my_patchstatus['to_install'][to_key]['unpatched_rpms']):
            for patch_rpm in sorted(my_patchstatus['to_install'][to_key]['patch'].rpmlist):
                if patch_rpm.name == system_rpm.name:
                   if patch_rpm.rhversion[0] == system_rpm.rhversion[0]:
                      print '   ', \
                            system_rpm.name, system_rpm.version_string, \
                            '<', patch_rpm.version_string

        # Found patched rpms (if any are found)
        if my_patchstatus['to_install'][to_key]['patched_rpms']:
           for system_rpm in sorted(my_patchstatus['to_install'][to_key]['patched_rpms']):
               for patch_rpm in sorted(my_patchstatus['to_install'][to_key]['patch'].rpmlist):
                   if patch_rpm.name == system_rpm.name:
                      if patch_rpm.rhversion[0] == system_rpm.rhversion[0]:
                         print '   ', \
                               system_rpm.name, system_rpm.version_string, \
                               '=>', patch_rpm.version_string


        print ''

    print 'RHAs that are installed on {}:'.format(hostname)
    print ''
    for inst_key in sorted(my_patchstatus['installed']):
        # RHA ID
        print my_patchstatus['installed'][inst_key]['patch'].rhalist[0]

        # Linked CVEs
        for cve in my_patchstatus['installed'][inst_key]['patch'].cvelist:
            print ' ', cve.name, \
                  '-', cve.rating(),
            if cve.cvss > 1:
               print '-', cve.score, '(cvss{})'.format(cve.cvss)
            else:
               print ''

        # Found patched rpms
        for system_rpm in sorted(my_patchstatus['installed'][inst_key]['patched_rpms']):
            for patch_rpm in sorted(my_patchstatus['installed'][inst_key]['patch'].rpmlist):
                if patch_rpm.name == system_rpm.name:
                   if patch_rpm.rhversion[0] == system_rpm.rhversion[0]:
                      print '   ', \
                            system_rpm.name, system_rpm.version_string, \
                            '=>', patch_rpm.version_string

        print ''

    print 'Not applicable RHAs for {}:'.format(hostname)
    print ''
    for na_key in sorted(my_patchstatus['na']):
        # RHA ID
        print my_patchstatus['na'][na_key]['patch'].rhalist[0]

        # Linked CVEs
        for cve in my_patchstatus['na'][na_key]['patch'].cvelist:
            print ' ', cve.name, \
                  '-', cve.rating(),
            if cve.cvss > 1:
               print '-', cve.score, '(cvss{})'.format(cve.cvss)
            else:
               print ''
        print ''
# =======================================================================


# =======================================================================
# get_system_rpmlist
#
# Get rpm list from system
# =======================================================================
def get_system_rpmlist():

    my_system_rpmlist = []

    cmd = ['/usr/bin/rpm \
            -qa --queryformat "%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}\\n"']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              shell=True)

    out, err = p.communicate()
    p_status = p.wait()

    lines = out.split('\n')

    for line in lines:
	if line.strip():
           my_system_rpmlist.append(my_rpm(line.replace('(none)','0')))

    return my_system_rpmlist
# =======================================================================


# =======================================================================
# main
# =======================================================================

# Old routine to print all patches
#for rhelversion in rhelversions:
#    patchlist[rhelversion] = get_patchlist(rhelversion)

#for rhelversion in rhelversions:
#    print '*****'
#    print rhelversion
#    print '*****'
#    print_patchlist(patchlist[rhelversion])

# Script runson system, so it needs only
# to check the the RHAs for this major release
rhelversion = 'RHEL'+rhel_major

patchlist[rhelversion] = get_patchlist(rhelversion)
# Print (extra check)
#print_patchlist(patchlist[rhelversion])

rpmlist = get_system_rpmlist()

# Old routine to print all installed rpms

#print '*****'
#print 'system'
#print '*****'
#for rpm in rpmlist:
#    print '   ', rpm.name, \
#          '=', rpm.version_string,
#    if rpm.rhversion > 0:
#       print '({})'.format(rpm.rhversion)
#    else:
#       print ''

patchstatus = check_patchlist(patchlist[rhelversion], rpmlist)
print_patchstatus(patchstatus)

