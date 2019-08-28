#!/usr/bin/python

# =======================================================================
# Monkey patch ElementTree
import xml.etree.ElementTree as ET

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

xml_tree = ET.parse('./com.redhat.rhsa-RHEL7.xml')

#print xml_tree

oval_definitions = xml_tree.getroot()
for oval_subset in oval_definitions:
    #print (oval_subset.tag, "->", oval_subset.__dict__)
    print ""

    if oval_subset.tag == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}definitions':
       for oval_definition in oval_subset:

	   #print oval_definition.tag, "-> ", oval_definition.__dict__
	   patch_definition = oval_definition.attrib

	   print patch_definition['id'], " ", patch_definition['version']

	   for patch_data in oval_definition:
	       #print patch_data.tag, "-> ", patch_data.__dict__
	       # Get CVE ID
	       if patch_data.tag == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}metadata':
		  for metadata_data in patch_data:
		      if metadata_data.tag.endswith('reference'):
			 #print ""
			 #print metadata.__dict__
			 #print ""
			 if metadata_data.attrib['source'] == 'CVE':
			    print "  CVE reference: ", metadata_data.attrib['ref_id']

		  # get CVSS score of the CVE with this patch
	          if metadata_data.tag == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}advisory':
		     for advisory_data in metadata_data:
			 # Assumption: CVSS3 score takes president over CVSS2
		         if 'cvss3' in advisory_data.keys():
			    cve = advisory_data.attrib['href'].split('/')[-1]
			    score_txt = advisory_data.attrib['cvss3'].split('/')[0]
			    score = float(score_txt)
			    severity = 'None'

			    if score > 8.9:
			       severity = 'Critical'
			    elif score > 6.9:
			       severity = 'High'
			    elif score > 3.9:
			       severity = 'Medium'
			    elif score > 0:
			       severity = 'Low'
			       
			    print " ", cve, "-" , score, "-", severity, "(cvss3)"
		         elif 'cvss2' in advisory_data.keys():
			    cve = advisory_data.attrib['href'].split('/')[-1]
			    score_txt = advisory_data.attrib['cvss2'].split('/')[0]
			    score = float(score_txt)
			    severity = 'Low'

			    if score > 6.9:
			       severity = 'High'
			    elif score > 3.9:
			       severity = 'Medium'
			       
			    print " ", cve, "-" , score, "-", severity, "(cvss2)"

	       # Weed trough criteria.
	       # AT 1st level we alwais have criteria
	       # at 2nd and later levels it is possible to find a criterion
	       # with package name and version we need to store
	       if patch_data.tag == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria':
		  for criteria2 in patch_data:
		      if criteria2.tag == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria':
			 for criteria3 in criteria2:
			     if criteria3.tag == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria':
			        for criterion in criteria3:
			            if criterion.tag == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion':
				       if 'is earlier than' in criterion.attrib['comment']:
				          comment = criterion.attrib['comment'].split()
				          print "   ", comment[0], "<", comment[-1]
			     elif criteria3.tag == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion':
				if 'is earlier than' in criteria3.attrib['comment']:
				   comment = criteria3.attrib['comment'].split()
				   print "   ", comment[0], "<", comment[-1]
		      elif criteria2.tag == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion':
			 if 'is earlier than' in criteria2.attrib['comment']:
			    comment = criteria2.attrib['comment'].split()
			    print "   ", comment[0], "<", comment[-1]

	   # Empty line to get a nice layout
	   print ""
