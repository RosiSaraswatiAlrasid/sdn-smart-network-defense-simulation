from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib import hub
import json, time, threading
from collections import defaultdict
from datetime import datetime

class SmartDefenseController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SmartDefenseController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.blocked_ips = set()
        self.blocked_ips_log = set()
        self.packet_count = defaultdict(int)      # count per IP
        self.port_scan_tracker = defaultdict(set) # port scan detection
        self.alerts = []                           # log IDS alerts
        self.stats = {"total_packets": 0, "blocked": 0, "alerts": 0}

        # Threshold deteksi serangan
        self.DOS_THRESHOLD = 10      # paket/detik
        self.PORTSCAN_THRESHOLD = 5  # port berbeda dalam 5 detik

        # Mulai monitor thread
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("=== Smart Defense System AKTIF ===")

    def _monitor(self):
        """Reset counter setiap 5 detik"""
        while True:
            hub.sleep(5)
            # Cek DoS
            for ip, count in list(self.packet_count.items()):
                if count > self.DOS_THRESHOLD and ip not in self.blocked_ips:
                    self._add_alert("DoS Attack", ip, f"{count} paket/5detik")
                    self.blocked_ips.add(ip)
                    self.blocked_ips_log.add(ip)
                    self.stats["blocked"] += 1
            # Reset counter
            self.packet_count.clear()
            self.port_scan_tracker.clear()
            self.blocked_ips.clear()
            state = {
                "stats": dict(self.stats),
                "alerts": self.alerts[-50:],
                "blocked_ips": list(self.blocked_ips_log)
            }
            with open('/tmp/defense_state.json', 'w') as f:
                json.dump(state, f)

    def _add_alert(self, attack_type, src_ip, detail):
        alert = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": attack_type,
            "src_ip": src_ip,
            "detail": detail
        }
        self.alerts.append(alert)
        self.stats["alerts"] += 1
        self.logger.warning(f"[ALERT] {attack_type} dari {src_ip}: {detail}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install default flow: kirim semua paket ke controller dulu"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

    def _add_flow(self, datapath, priority, match, actions, idle=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle, match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    def _block_ip(self, datapath, ip):
        """Tambahkan flow rule untuk blokir IP"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        self._add_flow(datapath, 100, match, [])  # actions kosong = drop
        self.logger.warning(f"[FIREWALL] IP {ip} DIBLOKIR!")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.stats["total_packets"] += 1

        # === IDS: Analisis IP ===
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src

            # Cek blacklist
            if src_ip in self.blocked_ips:
                self._block_ip(datapath, src_ip)
                return

            # Hitung paket per IP (deteksi DoS)
            self.packet_count[src_ip] += 1

            # Deteksi Port Scan (TCP ke banyak port berbeda)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                self.port_scan_tracker[src_ip].add(tcp_pkt.dst_port)
                if len(self.port_scan_tracker[src_ip]) > self.PORTSCAN_THRESHOLD:
                    if src_ip not in self.blocked_ips:
                        self._add_alert("Port Scan", src_ip,
                            f"{len(self.port_scan_tracker[src_ip])} port discanned")
                        self.blocked_ips.add(src_ip)
                        self.blocked_ips_log.add(src_ip)
                        self._block_ip(datapath, src_ip)
                        return

            # Deteksi ICMP Flood
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and self.packet_count[src_ip] > 50:
                self._add_alert("ICMP Flood", src_ip,
                    f"{self.packet_count[src_ip]} ICMP paket")

            # Deteksi UDP Flood
            udp_pkt = pkt.get_protocol(udp.udp)
            if udp_pkt and self.packet_count[src_ip] > self.DOS_THRESHOLD:
                self._add_alert("UDP FlooD", src_ip,
                    f"{self.packet_count[src_ip]} UDP Paket")

        # === L2 Learning Switch ===
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst,
                                    eth_src=src)
            self._add_flow(datapath, 1, match, actions, idle=10)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
