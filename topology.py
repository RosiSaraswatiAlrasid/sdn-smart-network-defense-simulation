from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

def create_topology():
    net = Mininet(controller=RemoteController,
                  switch=OVSSwitch,
                  link=TCLink)

    # Tambah Remote Controller (Ryu)
    c0 = net.addController('c0',
                            controller=RemoteController,
                            ip='127.0.0.1',
                            port=6633)

    # Tambah Switch
    s1 = net.addSwitch('s1')

    # Tambah Host (simulasi jaringan)
    h1 = net.addHost('h1', ip='10.0.0.1/24')  # User normal
    h2 = net.addHost('h2', ip='10.0.0.2/24')  # User normal
    h3 = net.addHost('h3', ip='10.0.0.3/24')  # Calon penyerang
    server = net.addHost('server', ip='10.0.0.100/24')  # Server target

    # Koneksi
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(server, s1)

    net.start()
    print("\n=== Topologi SDN aktif ===")
    print("h1 (10.0.0.1) - User normal")
    print("h2 (10.0.0.2) - User normal")
    print("h3 (10.0.0.3) - Attacker simulation")
    print("server (10.0.0.100) - Target server")
    print("\nKetik 'help' untuk daftar perintah Mininet")
    print("Ketik 'exit' untuk keluar\n")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
