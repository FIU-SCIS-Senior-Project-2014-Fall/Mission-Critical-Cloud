#!/usr/bin/env python

from ipoplib import *
import socket
import sys
from struct import *


class MCCVPNUdpServer(UdpServer):
    def __init__(self, user, password, host, ip4):
        UdpServer.__init__(self, user, password, host, ip4)
        self.idle_peers = {}
        self.user = user
        self.password = password
        self.host = host
        self.ip4 = ip4
        self.uid = gen_uid(ip4)
        self.vpn_type = "GroupVPN"
        self.ctrl_conn_init()

        self.uid_ip_table = {}
        parts = CONFIG["ip4"].split(".")
        ip_prefix = parts[0] + "." + parts[1] + "."
        for i in range(0, 255):
            for j in range(0, 255):
                ip = ip_prefix + str(i) + "." + str(j)
                uid = gen_uid(ip)
                self.uid_ip_table[uid] = ip

        if CONFIG["icc"]:
            self.inter_controller_conn()
        
        if CONFIG["switchmode"]:
            self.arp_table = {}

        if "network_ignore_list" in CONFIG:
            logging.debug("network ignore list")
            make_call(self.sock, m="set_network_ignore_list",\
                             network_ignore_list=CONFIG["network_ignore_list"])


    def ctrl_conn_init(self):
        do_set_logging(self.sock, CONFIG["tincan_logging"])
        do_set_cb_endpoint(self.sock, self.sock.getsockname())

        if not CONFIG["router_mode"]:
            do_set_local_ip(self.sock, self.uid, self.ip4, gen_ip6(self.uid),
                             CONFIG["ip4_mask"], CONFIG["ip6_mask"],
                             CONFIG["subnet_mask"], CONFIG["switchmode"])
        else:
            do_set_local_ip(self.sock, self.uid, CONFIG["router_ip"],
                           gen_ip6(self.uid), CONFIG["router_ip4_mask"],
                           CONFIG["router_ip6_mask"], CONFIG["subnet_mask"])

        do_register_service(self.sock, self.user, self.password, self.host)
        do_set_switchmode(self.sock, CONFIG["switchmode"])
        do_set_trimpolicy(self.sock, CONFIG["trim_enabled"])
        do_get_state(self.sock)

    def create_connection(self, uid, data, nid, sec, cas, ip4):
        do_create_link(self.sock, uid, data, nid, sec, cas)
        if (CONFIG["switchmode"] == 1):
            do_set_remote_ip(self.sock, uid, ip4, gen_ip6(uid))
        else: 
            do_set_remote_ip(self.sock, uid, ip4, gen_ip6(uid))

    def trim_connections(self):
        for k, v in self.peers.iteritems():
            if "fpr" in v and v["status"] == "offline":
                if v["last_time"] > CONFIG["wait_time"] * 2:
                    do_send_msg(self.sock, "send_msg", 1, k,
                                "destroy" + self.ipop_state["_uid"])
                    do_trim_link(self.sock, k)
            if CONFIG["on-demand_connection"] and v["status"] == "online": 
                if v["last_active"] + CONFIG["on-demand_inactive_timeout"]\
                                                              < time.time():
                    logging.debug("Inactive, trimming node:{0}".format(k))
                    do_send_msg(self.sock, 1, "send_msg", k,
                                "destroy" + self.ipop_state["_uid"])
                    do_trim_link(self.sock, k)
 
    def ondemand_create_connection(self, uid, send_req):
        logging.debug("idle peers {0}".format(self.idle_peers))
        peer = self.idle_peers[uid]
        fpr_len = len(self.ipop_state["_fpr"])
        fpr = peer["data"][:fpr_len]
        cas = peer["data"][fpr_len + 1:]
        ip4 = self.uid_ip_table[peer["uid"]]
        logging.debug("Start mutual creating connection")
        if send_req:
            do_send_msg(self.sock, "send_msg", 1, uid, fpr)
        self.create_connection(peer["uid"], fpr, 1, CONFIG["sec"], cas, ip4)

    def create_connection_req(self, data):
        version_ihl = struct.unpack('!B', data[54:55])
        version = version_ihl[0] >> 4
        if version == 4:
            s_addr = socket.inet_ntoa(data[66:70])
            d_addr = socket.inet_ntoa(data[70:74])
        elif version == 6:
            s_addr = socket.inet_ntop(socket.AF_INET6, data[62:78])
            d_addr = socket.inet_ntop(socket.AF_INET6, data[78:94])
            # At present, we do not handle ipv6 multicast
            if d_addr.startswith("ff02"):
                return

        uid = gen_uid(d_addr)
        try:
            msg = self.idle_peers[uid]
        except KeyError:
            logging.error("Peer {0} is not logged in".format(d_addr))
            return
        logging.debug("idle_peers[uid] --- {0}".format(msg))
        self.ondemand_create_connection(uid, send_req=True)


    def parse(self, packet):

        logging.debug("PARSING LOCAL PACKET")
      
        parsed_packet = {}

        #parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])

        #Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8 :
            #Parse IP header
            #take first 20 characters for the ip header
            ip_header = packet[eth_length:20+eth_length]

            #now unpack them
            iph = unpack('!BBHHHBBH4s4s' , ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);

            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size
            #get data from the packet
            #data = packet[h_size:]


            # build parsed_packet object
            parsed_packet = {
              "ip_header":ip_header
              ,"ttl":ttl
              ,"protocol":protocol
              ,"source":s_addr
              ,"dest":d_addr
              ,"icmp_header":icmp_header
              ,"icmp_type":icmp_type
              ,"code":code
              ,"checksum":checksum
              ,"h_size":h_size
              ,"data_size":data_size
              ,"data":packet
              ,"addr":addr
            }
            return parsed_packet

        else:
            logging.debug("Not an Ethernet Packet")
            return None 

    
    def multicast(self, msg, dest):
        logging.debug("Multicasting local packet")
        # Sanity Check
        if CONFIG['mcc_type'] == 1:
            logging.debug("MCC Type is not multicast; This should not happen")
            logging.debug("Failure Exiting...")
            sys.exit()

        uid = gen_uid(dest)

        for f in range(0, CONFIG['mcc_forwards']):
            rand_dest = self.peers[random.sample(self.peers, 1)]
            if rand_dest and self.peers[rand_dest]['status'] != offline:
                rand_dest_ip6  = rand_dest['ip6']
                logging.debug("RAND_DEST = %s, RAND_DEST_IP6 = %s", rand_dest, rand_dest_ip6)
                send_packet_to_remote(self.cc_sock, msg, rand_dest_ip6)

        if uid in self.peers and self.peers[uid]['status'] != offline:
            dest_ip6 = self.peers[uid]['ip6']
            logging.debug("DEST = %s, DEST_IP6 = %s", dest, dest_ip6)
            send_packet_to_remote(self.cc_sock, msg, dest_ip6)
        # else:
            # Do nothing


    # Generates a new random path from the source (this vm) to the destination vm
    # within the required latency bounds
    #
    # @param max The maximum allowed latency
    # @param min The minimum allowed latency
    # @param dest The destination vm
    #
    # @return the new path paths
    
    def find_path(self, max, min, dest):

        # get required number of hops
        hop_count = HOP_COUNT

        # this line makes it so that our max hop count
        # is no greater than the number of peers in our cloud.
        if hop_count > len(self.peers):
            hop_count = len(self.peers)

        paths = []

        guest_uid = gen_uid(dest)
        logging.debug ("Self.Peers = %s", self.peers )
        logging.debug ( "Self.Peerslist = %s", self.peerlist )

        if hop_count == 0:
            # make hop final destination
            if dest in self.peers:
              logging.debug("0 HOP - FOUND DEST IN PEERS LIST")
              paths.append(self.peers[guest_uid]) # final dest
              logging.debug( "PATHS = %s",  paths )
              return paths
            else:
              return None

        # NOTE: RANDOMIZATION ALGORITHM
        # _______________________________________________________________________________________________________
        # | Now the question becomes how many paths do we want to generate?                                      |
        # | Ideally we would want to generate ALL possible paths present in our network from source              |
        # | to destination. In order to do this we would need to introduce the incomplete gamma function         |
        # | Let P_n (p sub n) be the total number of paths from source u to destination v and the remainder      |
        # | of the graph be w. Then P_n = e(n-3)2G(n-3, 1)+n-2, where e is the base of the natural logarithm.    |
        # |                                                                                                      |
        # | This is all good, however the sequence explodes from after n = 7 i.e. 1, 3, 11, 49, 261, 1631, ...   |
        # |                                                                    n=3^           n=7^               |
        # | One would need to calculate the computational complexity of the random.sample function in Python to  |
        # | determine the feasibility of the above approach. However this is beyond the scope of this project    |
        # | therefore for the sake of simplicity we shall use 1 path of hop_count length.                        |
        # | The feasibility study and implementation of the aforementioned algorithm shall be future work.       |
        # |______________________________________________________________________________________________________|


        # add hop count random elements from peers set
        # make hop_count random samples of length hop_count
        # and append that set into paths.
        # see above if hop_count is greater than peers
        logging.debug("GUEST UID = %s", self.peers[guest_uid])

        if guest_uid in self.peers and self.peers[guest_uid]['status'] == 'online':
          for i in range(0, hop_count):
              logging.debug("RANDOM SAMPLE = %s", random.sample(self.peers, hop_count))
              paths.append(random.sample(self.peers, hop_count))

        logging.debug( "PATHS = %s",  paths )

        return paths


    
    # Wrapper for find_path. Fixes max and min latency vars.
    # @returns a randomly chosen path.

    def calc_route(self, source, dest):
        # Check if able to calculate route by checking
        # the status of the peerlist.
        # if there is no viable connection to the dest
        # by a peer than we cannot route the packet and 
        # no route exists.
        # if so return false
        if len(self.peers) == 0 or len(self.peerlist) == 0:
            logging.debug("No peers; cannot calculate route!")
            # if route cannot be calculated 
            # packet should not be changed
            return False

        # get some info from a future traffic function
        latency = calc_latency()
        if isinstance(CONFIG['min_latency'], int) and isinstance(CONFIG['max_latency'], int):
            if CONFIG['min_latency'] > CONFIG['max_latency']:# error perhaps swap max and min values
                max_latency = CONFIG['min_latency']
                min_latency = CONFIG['max_latency']
            else:
                max_latency = CONFIG['max_latency']
                min_latency = CONFIG['min_latency']
        else: pass
            # Raise error

        # choose a random path from the peers set and return it
        return self.find_path(max_latency, min_latency, dest)

    def local_packet_handle(self, source, dest, packet):
        route = self.calc_route(source, dest)
        if not(route):
            # no viable route to packet
            # handle packet directly
            # do nothing
            return None

        else:
            logging.debug("route = %s", route)
            if CONFIG['mcc_type'] == 0:
                return self.multicast(packet)

            packet = self.wrap(route, packet)
            
            make_remote_call(self.sock, d_addr, CONFIG['svpn_port'], tincan_packet, packet)
            logging.debug( "Local Packet Route Calculated and Sent!" )

        return

    def serve(self):
        socks, _, _ = select.select(self.sock_list, [], [], CONFIG["wait_time"])
        for sock in socks:
            if sock == self.sock or sock == self.sock_svr:
                #---------------------------------------------------------------
                #| offset(byte) |                                              |
                #---------------------------------------------------------------
                #|      0       | ipop version                                 |
                #|      1       | message type                                 |
                #|      2       | Payload (JSON formatted control message)     |
                #---------------------------------------------------------------
                data, addr = sock.recvfrom(CONFIG["buf_size"])
                if data[0] != ipop_ver:
                    logging.debug("ipop version mismatch: tincan:{0} controller"
                                  ":{1}" "".format(data[0].encode("hex"), \
                                   ipop_ver.encode("hex")))
                    sys.exit()
                if data[1] == tincan_control:
                    msg = json.loads(data[2:])
                    logging.debug("recv %s %s" % (addr, data[2:]))
                    msg_type = msg.get("type", None)
                    if msg_type == "echo_request":
                        make_remote_call(self.sock_svr, m_type=tincan_control,\
                          dest_addr=addr[0], dest_port=addr[1], payload=None,\
                          type="echo_reply")
                    if msg_type == "local_state":
                        self.ipop_state = msg
                    elif msg_type == "peer_state": 
                        if msg["status"] == "offline" or "stats" not in msg:
                            self.peers[msg["uid"]] = msg
                            self.trigger_conn_request(msg)
                            continue
                        stats = msg["stats"]
                        total_byte = 0
                        for stat in stats:
                            total_byte += stat["sent_total_bytes"]
                            total_byte += stat["recv_total_bytes"]
                        msg["total_byte"]=total_byte
                        logging.debug("self.peers:{0}".format(self.peers))
                        if not msg["uid"] in self.peers:
                            msg["last_active"]=time.time()
                        elif not "total_byte" in self.peers[msg["uid"]]:
                            msg["last_active"]=time.time()
                        else:
                            if msg["total_byte"] > \
                                         self.peers[msg["uid"]]["total_byte"]:
                                msg["last_active"]=time.time()
                            else:
                                msg["last_active"]=\
                                        self.peers[msg["uid"]]["last_active"]
                        self.peers[msg["uid"]] = msg
    
                    # we ignore connection status notification for now
                    elif msg_type == "con_stat": pass
                    elif msg_type == "con_req": 
                        if CONFIG["on-demand_connection"]: 
                            self.idle_peers[msg["uid"]]=msg
                        else:
                            if self.check_collision(msg_type,msg["uid"]): 
                                continue
                            fpr_len = len(self.ipop_state["_fpr"])
                            fpr = msg["data"][:fpr_len]
                            cas = msg["data"][fpr_len + 1:]
                            ip4 = self.uid_ip_table[msg["uid"]]
                            self.create_connection(msg["uid"], fpr, 1, 
                                                   CONFIG["sec"], cas, ip4)
                    elif msg_type == "con_resp":
                        if self.check_collision(msg_type, msg["uid"]): continue
                        fpr_len = len(self.ipop_state["_fpr"])
                        fpr = msg["data"][:fpr_len]
                        cas = msg["data"][fpr_len + 1:]
                        ip4 = self.uid_ip_table[msg["uid"]]
                        self.create_connection(msg["uid"], fpr, 1, 
                                               CONFIG["sec"], cas, ip4)
    
                    # send message is used as "request for start mutual 
                    # connection"
                    elif msg_type == "send_msg": 
                        if CONFIG["on-demand_connection"]:
                            if msg["data"].startswith("destroy"):
                                do_trim_link(self.sock, msg["uid"])
                            else:
                                self.ondemand_create_connection(msg["uid"], 
                                                                False)
                   
                # If a packet that is destined to yet no p2p connection 
                # established node, the packet as a whole is forwarded to 
                # controller
                #|-------------------------------------------------------------|
                #| offset(byte) |                                              |
                #|-------------------------------------------------------------|
                #|      0       | ipop version                                 |
                #|      1       | message type                                 |
                #|      2       | source uid                                   |
                #|     22       | destination uid                              |
                #|     42       | Payload (Ethernet frame)                     |
                #|-------------------------------------------------------------|
                elif data[1] == tincan_packet:
 
                    # For Francois 
                    # --------------------------------------------------------
                    if data[54:56] == "\x08\x00":
                        logging.debug("IPv4 Packet is forwarded")
                        dump(data)
                        msg = data[2:]
                        src = data[2:22]
                        dest = data[22:42]
                        payload = data[42:]

                        dump(msg)
                        dump(src)
                        dump(dest)
                        dump(payload)
                        logging.debug("PAYLOAD = %s", mac_b2a(payload[:6]))
                        logging.debug("PAYLOAD = %s", mac_b2a(payload[6:12]))
                        dump(payload[12:16])
                        dump(payload[16:18])
                        dump(payload[18:])

                        parsed_packet = self.parse(data)
                        if(parsed_packet and parsed_packet['data'][0] not in control_packet_types):
                          if str(parsed_packet["source"]) == CONFIG['ip4']:
                            if CONFIG['mcc_type'] == 0:
                                self.multicast(msg, parsed_packet["dest"])
                            else:
                                self.local_packet_handle(parsed_packet["source"], parsed_packet["dest"], parsed_packet["data"])
                        # dest = ("fd50:0dbc:41f2:4a3c:477c:cb36:7fd5:104c", 30000)
                        # send_packet_to_remote(self.cc_sock, msg, dest)
                        logging.debug("CONTINUING")
                        continue
                    # ----------------------------------------For Francois----





                    # Ignore IPv6 packets for log readability. Most of them are
                    # Multicast DNS packets
                    if data[54:56] == "\x86\xdd":
                        continue
                    logging.debug("IP packet forwarded \nversion:{0}\nmsg_type:"
                        "{1}\nsrc_uid:{2}\ndest_uid:{3}\nsrc_mac:{4}\ndst_mac:{"
                        "5}\neth_type:{6}".format(data[0].encode("hex"), \
                        data[1].encode("hex"), data[2:22].encode("hex"), \
                        data[22:42].encode("hex"), data[42:48].encode("hex"),\
                        data[48:54].encode("hex"), data[54:56].encode("hex")))
 
                    if not CONFIG["on-demand_connection"]:
                        continue
                    if len(data) < 16:
                        continue
                    self.create_connection_req(data[2:])
     
                else:
                    logging.error("Unknown type message")
                    logging.debug("{0}".format(data[0:].encode("hex")))
                    sys.exit()

            elif sock == self.cc_sock:
                data, addr = sock.recvfrom(CONFIG["buf_size"])
                logging.debug("ICC packet received from {0}".format(addr))
                # For Francios  ----------------------------------------
                msg = ""
                msg += null_uid
                msg += null_uid
                msg += mac_a2b(self.ipop_state["_mac"])
                msg += data[6:12] 
                msg += data[12:]

                send_packet(self.sock, data)
                # ----------------------------------------For Francois
                #self.icc_packet_handle(addr, data)
                
            else:
                logging.error("Unknown type socket")
                sys.exit()
    
def main():
    parse_config()
    server = MCCVPNUdpServer(CONFIG["xmpp_username"], CONFIG["xmpp_password"],
                       CONFIG["xmpp_host"], CONFIG["ip4"])
    set_global_variable_server(server)
    if CONFIG["stat_report"]:
        server.report()
    last_time = time.time()
    while True:
        server.serve()
        time_diff = time.time() - last_time
        if time_diff > CONFIG["wait_time"]:
            server.trim_connections()
            do_get_state(server.sock)
            last_time = time.time()

if __name__ == "__main__":
    main()

