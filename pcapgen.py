import sys
import binascii

#Global header for pcap 2.4
pcap_global_header =   ('D4 C3 B2 A1'   
                        '02 00'         #File format major revision (i.e. pcap <2>.4)  
                        '04 00'         #File format minor revision (i.e. pcap 2.<4>)   
                        '00 00 00 00'     
                        '00 00 00 00'     
                        'FF FF 00 00'     
                        '01 00 00 00')

#pcap packet header that must preface every packet
pcap_packet_header =   ('AA 77 9F 47'     
                        '90 A2 04 00'     
                        'XX XX XX XX'   #Frame Size (little endian) 
                        'YY YY YY YY')  #Frame Size (little endian)

eth_header =   ('00 00 00 00 00 00'     #Source Mac    
                '00 00 00 00 00 00'     #Dest Mac  
                '08 00')                #Protocol (0x0800 = IP)

ip_headerudp =    ('45'                    #IP version and header length (multiples of 4 bytes)   
                '00'                      
                'XX XX'                 #Length - will be calculated and replaced later
                '00 00'                   
                '40 00 40'                
                '11'                    #Protocol (0x11 = UDP)          
                'YY YY'                 #Checksum - will be calculated and replaced later      
                '7F 00 00 01'           #Source IP (Default: 127.0.0.1)         
                '8F 10 01 01')          #Dest IP (Default: 127.0.0.1) 

ip_headertcp =    ('45'                    #IP version and header length (multiples of 4 bytes)   
                '00'                      
                'XX XX'                 #Length - will be calculated and replaced later
                '00 00'                   
                '40 00 40'                
                '06'                    #Protocol (0x11 = UDP)          
                'YY YY'                 #Checksum - will be calculated and replaced later      
                'srcip'           #Source IP (Default: 127.0.0.1)         
                'dstip')          #Dest IP (Default: 127.0.0.1) 

udp_header =   ('80 01'                   
                'XX XX'                 #Port - will be replaced later                   
                'YY YY'                 #Length - will be calculated and replaced later        
                '00 00')

tcp_header =   ('srcport'
                'dstport'
                'bd 9e f5 f2'   #sequence number
                '00 10 01 11'   #ack number
                '80 10 00 ed'   #offset Reserved TCP flags Window
                '00 00 00 00'
                '01 01 08 0a 00 11 02 97 3f cf 71 9b' #options
                )

                
def getByteLength(str1):
    return len(''.join(str1.split())) / 2

def writeByteStringToFile(bytestring, pcapfile):
    bytelist = bytestring.split()  
    bytes = binascii.a2b_hex(''.join(bytelist))
    pcapfile.write(bytes)

def generatePCAP(message,port,pcapfile): 

    udp = udp_header.replace('XX XX',"%04x"%port)
    udp_len = getByteLength(message) + getByteLength(udp_header)
    udp = udp.replace('YY YY',"%04x"%udp_len)

    ip_len = udp_len + getByteLength(ip_header)
    ip = ip_header.replace('XX XX',"%04x"%ip_len)
    checksum = ip_checksum(ip.replace('YY YY','00 00'))
    ip = ip.replace('YY YY',"%04x"%checksum)
    
    pcap_len = ip_len + getByteLength(eth_header)
    hex_str = "%08x"%pcap_len
    reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
    pcaph = pcap_packet_header.replace('XX XX XX XX',reverse_hex_str)
    pcaph = pcaph.replace('YY YY YY YY',reverse_hex_str)

    bytestring = pcap_global_header + pcaph + eth_header + ip + udp + message
    writeByteStringToFile(bytestring, pcapfile)

def generatepcap(filename):
    pfile=open(filename,"wb")
    writeByteStringToFile(pcap_global_header,pfile)
    return pfile

def AppendTcpPacket(msg,srcip,srcport,dstip,dstport,pcapfile): 
    message="".join("%02x"%ord(c) for c in msg)
    tcp = tcp_header.replace('srcport',"%04x"%srcport)
    tcp = tcp.replace('dstport',"%04x"%dstport)
    tcp_len = getByteLength(message) + getByteLength(tcp_header)
#    tcp = tcp.replace('YY YY',"%04x"%tcp_len)

    ip = ip_headertcp.replace('srcip',srcip)
    ip = ip.replace('dstip',dstip)
    ip_len = tcp_len + getByteLength(ip_headertcp)
    ip = ip.replace('XX XX',"%04x"%ip_len)
    checksum = ip_checksum(ip.replace('YY YY','00 00'))
    ip = ip.replace('YY YY',"%04x"%checksum)
    
    pcap_len = ip_len + getByteLength(eth_header)
    hex_str = "%08x"%pcap_len
    reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
    pcaph = pcap_packet_header.replace('XX XX XX XX',reverse_hex_str)
    pcaph = pcaph.replace('YY YY YY YY',reverse_hex_str)

    bytestring = pcaph + eth_header + ip + tcp + message
    writeByteStringToFile(bytestring, pcapfile)

#Splits the string into a list of tokens every n characters
def splitN(str1,n):
    return [str1[start:start+n] for start in range(0, len(str1), n)]

#Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):

    #split into bytes    
    words = splitN(''.join(iph.split()),4)

    csum = 0;
    for word in words:
        csum += int(word, base=16)

    csum += (csum >> 16)
    csum = csum & 0xFFFF ^ 0xFFFF

    return csum


"""------------------------------------------"""
""" End of functions, execution starts here: """
"""------------------------------------------"""

#if len(sys.argv) < 2:
#        print 'usage: pcapgen.py output_file'
#        exit(0)
#
#msg="wo shi zhong guo ren"
#pcapfile=sys.argv[1]
#pfile=generatepcap(pcapfile)
#AppendTcpPacket(msg,srcip,srcport,dstip,dstport,pfile)  
#AppendTcpPacket("hahaha",srcip,srcport,dstip,dstport,pfile)  
#pfile.close()
