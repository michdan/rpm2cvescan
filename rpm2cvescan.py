#!/usr/bin/python

# =======================================================================
# Monkey patch ElementTree
import xml.etree.ElementTree as ET

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

tree = ET.parse('./com.redhat.rhsa-RHEL7.xml', OrderedXMLTreeBuilder())

root = tree.getroot()
for child in root.iter():
    #print(child.tag, child.attrib)

    # Get rhsa id and version
    if child.tag.endswith('definition'):
	print ""
	print child.attrib['id'], " ", child.attrib['version']

    # When CVE, get CVE ID
    if child.tag.endswith('reference'):
	if child.attrib['source'] == 'CVE':
	    print child.attrib['ref_id']

    # When ctiterion, get package name and version
    if child.tag.endswith('criterion'):
	if 'is earlier than' in child.attrib['comment']:
	    comment = child.attrib['comment'].split()
	    print comment[0], "<", comment[-1]

    # Get rhsa id and version
    if child.tag.endswith('cve'):
	if 'cvss2' in child.attrib.keys():
	    print "cvss2:", child.attrib['cvss2'].split('/')[0], child.attrib['href'].split('/')[-1]

	if 'cvss3' in child.attrib.keys():
	    print "cvss3:", child.attrib['cvss3'].split('/')[0], child.attrib['href'].split('/')[-1]

