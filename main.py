from scapy.all import rdpcap, wrpcap, PcapReader
from scapy.layers import inet, dns
import time
import glob


pcap = "var6.pcap"



packetNum = 1350000
myPackNum = 1350

vulnPattern = r"^192\.168\.50\.([1-2][0-9]|3[0-5])$"
vulnPackets = []
botmasterIPs = []
botIPs = []

start = time.perf_counter()
# packets = rdpcap("var6.pcap", packetNum)


print("=================")
print(pcap)
print("=================")
for pkt in PcapReader(pcap):
    if pkt[dns.DNS].qr == 1:
        if pkt[dns.DNS].ancount > 0:
            dnsIP = pkt[inet.IP].src
            botIP = pkt[inet.IP].dst
            answIP = pkt[dns.DNS].an.rdata
            urlQR = pkt[dns.DNS][dns.DNSQR].qname.decode("utf-8")

            # print(dnsIP + " answered to " + botIP + " with " + answIP)
            # print(pkt[dns.DNS].summary())
            # print(urlQR)

            if [answIP, urlQR] not in botmasterIPs:
                botmasterIPs.append([answIP, urlQR])
                print("Found new botmaster:")
                print("IP: ", answIP)
                print("URL: ", urlQR)
                print("Time: ", time.perf_counter() - start)
                print()
            if botIP not in botIPs:
                botIPs.append(botIP)
                print("Found new bot: ")
                print("IP: ", botIP)
                print("Time: ", time.perf_counter() - start)
                print()
            vulnPackets.append(pkt)
print("Botmaster servers:")
for ip, url in botmasterIPs:
    print(ip, " ", url)

print("Bots:")
for ip in botIPs:
    print(ip)

f_bots = open("bots.txt", "w+")
f_botmasters = open("botmasters.txt", "w+")

for botIP in botIPs:
    f_bots.write(botIP + "\n")
for botmasterIP, botmasterURL in botmasterIPs:
    f_botmasters.write(botmasterIP + "\t" + botmasterURL + "\n")

f_bots.close()
f_botmasters.close()


