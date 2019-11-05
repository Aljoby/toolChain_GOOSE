import xml.dom.minidom
from scapy.all import *


def readPCAP():
	packets = rdpcap('gooseTrace.pcap')
	for packet in packets:
		#print (packet.summary())
		#print (packet.show())
		#print (packet['Ethernet'].dst)
		#print (hexdump(packet.load))
		print (ls(packet))
		#print (packet.payload.show)
		#print (str(packet).encode("HEX"))
		print ("\n")
		break

	#print ("read GOOSe pcap file, to find stNum, sqNum, and MAC")
	stNum = 1
	sqNum = 5
	MAC = "00:1b:21:b5:8b:bd" 
	parse_check(stNum,sqNum, MAC)

def injectPKT(stNum,sqNum,MAC,data):
	print ("Inject pkt: based on the received parameters")
		#use scapy's send method, e.g., send(Ether(dst=MAC/goose.GOOSE(data))
def dosPKTs(stNum,sqNum,frq,data):
	for x in range(frq):
		print ("DOS pkts: based on the received parameters")
		#use scapy's send method, e.g., send(goose.GOOSE(data)) 


def parse_check(stNum,sqNum,MAC):
# use the parse() function to load and parse an XML file
   doc = xml.dom.minidom.parse("xmlFile.xml");
  
# print out the document node and the name of the first child tag
   #print doc.nodeName
   #print doc.firstChild.tagName
  


  

# get a list of XML tags from the document and print each one
   attacks = doc.getElementsByTagName("attack")
   print ("\n")
   print ("The xml file has %d defined attacks:" % attacks.length)
   for att in attacks:
     name = att.getAttribute("name")
     print (name)
     cond = att.getElementsByTagName("cond")[0]
     stNum_c = int (cond.getAttributeNode("stNum").nodeValue)
     sqNum_c = int (cond.getAttributeNode("sqNum").nodeValue)
    
     if name == "InjectPkt":
          MAC_c = cond.getAttributeNode("MAC").nodeValue
     if name == "DOSPkts":
          freq = int (cond.getAttributeNode("freq").nodeValue)


     payload = att.getElementsByTagName("payload")[0]
     stNum_p = int (payload.getAttributeNode("stNum").nodeValue)
     sqNum_p = int (payload.getAttributeNode("sqNum").nodeValue)
     data = payload.getAttributeNode("data").nodeValue


	 #print("cond :%s, payload :%s"% (cond.firstChild.data, payload.firstChild.data))
     #print ("stNum_c %d" % stNum_c)
     #print ("sqNum_c %d" % sqNum_c)
     #print ("MAC %s" % MAC)

     #print ("stNum_p %d" % stNum_p)
     #print ("sqNum_p %d" % sqNum_p)
     #print ("data %s" % data)

     if stNum_c == stNum and sqNum == sqNum_c :
        if name == "InjectPkt":
           if MAC_c == MAC :
              print ("packet should be injected by modifying stNum set to %d , sqNum set to %d , and data set to %s !" % (stNum_p , sqNum_p, data))
              injectPKT(stNum_p,sqNum_p,MAC_c,data)
        elif name == "DOSPkts":
              print ("%d packets should be flooded with stNum set to %d , sqNum set to %d , and data set to \" %s \"" % (freq,stNum_p , sqNum_p, data))
              dosPKTs(stNum_p,sqNum_p,freq,data)




if __name__ == "__main__":
  readPCAP()

