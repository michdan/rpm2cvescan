#!/usr/bin/python
import sys, getopt, os.path
import rpm
import subprocess
import xml.etree.ElementTree as ET

summary_only = False

if len(sys.argv) > 1:
   try:
      opts, args = getopt.getopt(sys.argv[1:],"hs",["summary"])
   except getopt.GetoptError:
      print sys.argv[0], '[-h] [-s] [--summary]'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print sys.argv[0], '[-h] [-s] [--summary]'
         sys.exit()
      elif opt in ("-s", "--summary"):
         summary_only = True

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
    if os.path.exists(my_filename):
       xml_tree = ET.parse(my_filename)
    else:
       print 'Can\'t access RHSA file', my_filename
       sys.exit(1)

    my_patchlist = []

    oval_definitions = xml_tree.getroot()
    for oval_subset in oval_definitions:

        if oval_subset.tag == namespace+'definitions':
           for oval_definition in oval_subset:

               patch_definition = oval_definition.attrib

               this_patch = my_patch(patch_definition['id'].split(':')[-1], patch_definition['version'])

               for patch_data in oval_definition:
                   # Get CVE ID
                   if patch_data.tag == namespace+'metadata':
                      for metadata_data in patch_data:
                          if metadata_data.tag.endswith('reference'):
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

    summary = {}
    summary['to_install'] = {}
    summary['to_install']['critical'] = 0
    summary['to_install']['high'] = 0
    summary['to_install']['medium'] = 0
    summary['to_install']['low'] = 0
    summary['to_install']['none'] = 0
    summary['to_install']['total'] = 0

    summary['installed'] = {}
    summary['installed']['critical'] = 0
    summary['installed']['high'] = 0
    summary['installed']['medium'] = 0
    summary['installed']['low'] = 0
    summary['installed']['none'] = 0
    summary['installed']['total'] = 0

    if not summary_only:
       print 'RHAs that need to be installed on {}:'.format(hostname)
       print ''

    for to_key in sorted(my_patchstatus['to_install']):
        # RHA ID
        if not summary_only:
           print my_patchstatus['to_install'][to_key]['patch'].rhalist[0]

        highest_score = 0.0
        summary['to_install']['total'] += 1

        # Linked CVEs
        for cve in my_patchstatus['to_install'][to_key]['patch'].cvelist:
            if not summary_only:
               print ' ', cve.name, \
                     '-', cve.rating(),
               if cve.cvss > 1:
                  print '-', cve.score, '(cvss{})'.format(cve.cvss)
               else:
                  print ''

            if cve.score > highest_score:
               highest_score = cve.score

        if cve.score > 8.9:
           summary['to_install']['critical'] += 1
        elif cve.score > 6.9:
           summary['to_install']['high'] += 1
        elif cve.score > 3.9:
           summary['to_install']['medium'] += 1
        elif cve.score > 0:
           summary['to_install']['low'] += 1
        else:
           summary['to_install']['none'] += 1

        # Found unpatched rpms
        for system_rpm in sorted(my_patchstatus['to_install'][to_key]['unpatched_rpms']):
            for patch_rpm in sorted(my_patchstatus['to_install'][to_key]['patch'].rpmlist):
                if patch_rpm.name == system_rpm.name:
                   if patch_rpm.rhversion[0] == system_rpm.rhversion[0]:
                      if not summary_only:
                         print '   ', \
                               system_rpm.name, system_rpm.version_string, \
                               '<', patch_rpm.version_string

        # Found patched rpms (if any are found)
        if my_patchstatus['to_install'][to_key]['patched_rpms']:
           for system_rpm in sorted(my_patchstatus['to_install'][to_key]['patched_rpms']):
               for patch_rpm in sorted(my_patchstatus['to_install'][to_key]['patch'].rpmlist):
                   if patch_rpm.name == system_rpm.name:
                      if patch_rpm.rhversion[0] == system_rpm.rhversion[0]:
                         if not summary_only:
                            print '   ', \
                                  system_rpm.name, system_rpm.version_string, \
                                  '=>', patch_rpm.version_string


        if not summary_only:
           print ''

    if not summary_only:
       print 'RHAs that are installed on {}:'.format(hostname)
       print ''
    for inst_key in sorted(my_patchstatus['installed']):
        # RHA ID
        if not summary_only:
           print my_patchstatus['installed'][inst_key]['patch'].rhalist[0]

        highest_score = 0.0
        summary['installed']['total'] += 1

        # Linked CVEs
        for cve in my_patchstatus['installed'][inst_key]['patch'].cvelist:
            if not summary_only:
               print ' ', cve.name, \
                     '-', cve.rating(),
               if cve.cvss > 1:
                  print '-', cve.score, '(cvss{})'.format(cve.cvss)
               else:
                  print ''

            if cve.score > highest_score:
               highest_score = cve.score

        if cve.score > 8.9:
           summary['installed']['critical'] += 1
        elif cve.score > 6.9:
           summary['installed']['high'] += 1
        elif cve.score > 3.9:
           summary['installed']['medium'] += 1
        elif cve.score > 0:
           summary['installed']['low'] += 1
        else:
           summary['installed']['none'] += 1

        # Found patched rpms
        for system_rpm in sorted(my_patchstatus['installed'][inst_key]['patched_rpms']):
            for patch_rpm in sorted(my_patchstatus['installed'][inst_key]['patch'].rpmlist):
                if patch_rpm.name == system_rpm.name:
                   if patch_rpm.rhversion[0] == system_rpm.rhversion[0]:
                      if not summary_only:
                         print '   ', \
                               system_rpm.name, system_rpm.version_string, \
                               '=>', patch_rpm.version_string

        if not summary_only:
           print ''

    if not summary_only:
       print 'Not applicable RHAs for {}:'.format(hostname)
       print ''
    for na_key in sorted(my_patchstatus['na']):
        # RHA ID
        if not summary_only:
           print my_patchstatus['na'][na_key]['patch'].rhalist[0]

        # Linked CVEs
        for cve in my_patchstatus['na'][na_key]['patch'].cvelist:
            if not summary_only:
               print ' ', cve.name, \
                     '-', cve.rating(),
               if cve.cvss > 1:
                  print '-', cve.score, '(cvss{})'.format(cve.cvss)
               else:
                  print ''
        if not summary_only:
           print ''

    print '           Tot Cri  Hi Med Low None'
    print '  Missing: %3d %3d %3d %3d %3d %3d' % \
                    ( summary['to_install']['total'], \
                        summary['to_install']['critical'], \
                        summary['to_install']['high'], \
                        summary['to_install']['medium'], \
                        summary['to_install']['low'], \
                        summary['to_install']['none'] )
    print 'Installed: %3d %3d %3d %3d %3d %3d' % \
                    ( summary['installed']['total'], \
                      summary['installed']['critical'], \
                      summary['installed']['high'], \
                      summary['installed']['medium'], \
                      summary['installed']['low'], \
                      summary['installed']['none'] )

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

           rpm_string = line.replace('(none)','0')

	   if ':' in line:
              rpm_name = line.split(':')[0].rsplit('-',1)[0]
           else:
              rpm_name = line.split('.')[0].rsplit('-',1)[0]

           if rpm_name != 'kernel':
              my_system_rpmlist.append(my_rpm(rpm_string))
           else:
              rpm_release = rpm_string.split('-')[-1]
              if len(rpm_release) != 6 and rpm_release[4:6] != 'el':
                 my_system_rpmlist.append(my_rpm(rpm_string))

    return my_system_rpmlist
# =======================================================================


# =======================================================================
# main
# =======================================================================

rhelversion = 'RHEL'+rhel_major

patchlist[rhelversion] = get_patchlist(rhelversion)

rpmlist = get_system_rpmlist()

patchstatus = check_patchlist(patchlist[rhelversion], rpmlist)
print_patchstatus(patchstatus)
