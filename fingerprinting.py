from scapy.all import *

#cambiar ip 
target_ip = "192.168.1.101"
open_port = 80   
closed_port = 81  

#enviar paquete y recibir respuesta
def send_packet_and_sniff(packet, timeout=2):
    response = sr1(packet, timeout=timeout)
    return response

# Función para analizar la respuesta
def analyze_response(response):
    if response is None:
        print("No response")
    elif response.haslayer(TCP):
        tcp_layer = response.getlayer(TCP)
        print(f"Received TCP packet from {response[IP].src} with flags {tcp_layer.flags}")
    elif response.haslayer(UDP):
        print(f"Received UDP packet from {response[IP].src}")
    elif response.haslayer(ICMP):
        print(f"Received ICMP packet from {response[IP].src} with type {response[ICMP].type}")
    else:
        print(f"Received packet from {response[IP].src}")

# Paquete P1: Enviar un paquete TCP desde el puerto 0 al puerto 0
packet_P1 = IP(dst=target_ip)/TCP(sport=0, dport=0, flags="S")
response_P1 = send_packet_and_sniff(packet_P1)
analyze_response(response_P1)

# Paquete P2: Enviar un paquete TCP desde un puerto distinto de 0 al puerto 0
packet_P2 = IP(dst=target_ip)/TCP(sport=12345, dport=0, flags="S")
response_P2 = send_packet_and_sniff(packet_P2)
analyze_response(response_P2)

# Paquete P3: Enviar un paquete TCP desde el puerto 0 a un puerto abierto
packet_P3 = IP(dst=target_ip)/TCP(sport=0, dport=open_port, flags="S")
response_P3 = send_packet_and_sniff(packet_P3)
analyze_response(response_P3)

# Paquete P4: Enviar un paquete TCP desde el puerto 0 a un puerto cerrado
packet_P4 = IP(dst=target_ip)/TCP(sport=0, dport=closed_port, flags="S")
response_P4 = send_packet_and_sniff(packet_P4)
analyze_response(response_P4)

# Paquete P5: Enviar un paquete UDP desde el puerto 0 al puerto 0
packet_P5 = IP(dst=target_ip)/UDP(sport=0, dport=0)
response_P5 = send_packet_and_sniff(packet_P5)
analyze_response(response_P5)

# Paquete P6: Enviar un paquete UDP desde el puerto 53 al puerto 0
packet_P6 = IP(dst=target_ip)/UDP(sport=53, dport=0)
response_P6 = send_packet_and_sniff(packet_P6)
analyze_response(response_P6)

# Paquete P7: Enviar un paquete UDP desde el puerto 0 a un puerto cerrado
packet_P7 = IP(dst=target_ip)/UDP(sport=0, dport=closed_port)
response_P7 = send_packet_and_sniff(packet_P7)
analyze_response(response_P7)
