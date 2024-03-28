import pyshark
import matplotlib.pyplot as plt
from collections import Counter

def analyze_dns_packets(filepath, output_file):
    # Charger le fichier pcap
    capture = pyshark.FileCapture(filepath)

    # Initialiser un dictionnaire pour les détails des requêtes DNS
    dns_requests_details = {}

    # Parcourir chaque paquet dans la capture
    for packet in capture:
        try:
            # Vérifier si le paquet contient une couche DNS
            if 'DNS' in packet:
                dns_layer = packet.dns
                
                # Vérifier si c'est une requête DNS et si elle contient le type désiré (A, AAAA, HTTPS)
                if hasattr(dns_layer, 'qry_type') and dns_layer.qry_type in ['1', '28', '65']:
                    query_type = 'A' if dns_layer.qry_type == '1' else 'AAAA' if dns_layer.qry_type == '28' else 'HTTPS'
                    domain_name = dns_layer.qry_name.lower()
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst

                    # Clé unique pour chaque combinaison de demande
                    request_key = (domain_name, src_ip, dst_ip, query_type)

                    # Compter le nombre de fois qu'une requête DNS spécifique a été faite
                    if request_key in dns_requests_details:
                        dns_requests_details[request_key] += 1
                    else:
                        dns_requests_details[request_key] = 1
        except Exception as e:
            print(f"Erreur lors de l'analyse du paquet: {e}")

    # Écrire les détails dans le fichier de sortie
    with open(output_file, 'w') as f:
        f.write("Domain Name | Source IP | Destination IP | Query Type | Count\n")
        for (domain_name, src_ip, dst_ip, query_type), count in dns_requests_details.items():
            f.write(f"{domain_name} | {src_ip} | {dst_ip} | {query_type} | {count} fois\n")

    print(f"Les détails des requêtes DNS ont été écrits dans {output_file}")

if __name__ == "__main__":
    pcap_file_path = "TRANSFERT/Capture_TR_20Mb.pcap"
    output_file = "DNS_info.txt"
    analyze_dns_packets(pcap_file_path, output_file)