from scapy.all import *
import socket
import sys
import os

if(os.name == "nt"):
	os.system("cls")
else:
	os.system("clear")

def check_connections():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind(('127.0.0.1', 80))
            server_socket.listen(1)
            print("Localhost dinlemesi başladı.")
            
            while True:
                client_socket, client_address = server_socket.accept()
                #print(f"Bağlantı geldi {client_address[0]}:{client_address[1]}]")

                # Gelen bağlantının URL'sini kontrol et
                request_data = client_socket.recv(1024).decode()
                if "GET /index.html" in request_data:
                    print("localhost/index.html sayfasına bağlantı alındı.")
                    # İstenilen işlemleri burada gerçekleştirebilirsiniz.
                client_socket.close()

    except KeyboardInterrupt:
        print("Program sonlandırıldı.")
        sys.exit(0)
      
def process_packet(packet):
	try:
		# ICMP paketlerini dinleme
		if packet.haslayer(ICMP):
			print("ICMP paketi alındı! Uyarı!")
			print(packet.summary())

		# POST paketlerini dinleme
		elif packet.haslayer(TCP) and packet.haslayer(Raw):
			tcp = packet[TCP]
			raw = packet[Raw].load.decode(errors='ignore')
			if "POST" in raw:
				print("POST paketi alındı! Uyarı!")
				print(f"Kaynak IP: {packet[IP].src}")
				print(f"Hedef IP: {packet[IP].dst}")
				print(f"POST Verisi: {raw}")

		# GET paketlerini dinleme
		elif packet.haslayer(TCP) and packet.haslayer(Raw):
			tcp = packet[TCP]
			raw = packet[Raw].load.decode(errors='ignore')
			if "GET" in raw:
				print("GET paketi alındı! Uyarı!")
				print(f"Kaynak IP: {packet[IP].src}")
				print(f"Hedef IP: {packet[IP].dst}")
				print(f"GET Verisi: {raw}")

		# SSH bağlantı paketlerini dinleme
		elif packet.haslayer(TCP) and packet[TCP].dport == 22:
			print("SSH paketi alındı! Uyarı!")
			print(f"Kaynak IP: {packet[IP].src}")
			print(f"Hedef IP: {packet[IP].dst}")

		# FTP bağlantı paketlerini dinleme
		elif packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
			print("FTP paketi alındı! Uyarı!")
			print(f"Kaynak IP: {packet[IP].src}")
			print(f"Hedef IP: {packet[IP].dst}")
	except KeyboardInterrupt:
		print("Program sonlandırıldı.")
		sys.exit(0)

try:
	print("Localhost dinlemesi başladı...")
	check_connections()
	print("Paket dinlemesi başladı...")
	sniff(filter="icmp or tcp and (port 80 or port 443)", prn=process_packet, store=1,iface="Wi-Fi")
except KeyboardInterrupt:
	print("Program sonlandırıldı.")
	sys.exit(1)

