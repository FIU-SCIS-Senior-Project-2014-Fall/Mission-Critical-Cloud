#!/usr/bin/env python

from ipoplib2 import *
from graph_tool.all import *
import socket
import fcntl
import struct
import itertools

xmpp_username = socket.gethostname()

'''
con_graph = graph_tool.generation.complete_graph(len(con_table), directed=True)

v_name = con_graph.new_vertex_property("string")
v_ip = con_graph.new_vertex_property("string")
v_uid = con_graph.new_vertex_property("string")
e_latency = con_graph.new_edge_property("double")
'''

'''
Gets the ip address of the specified interface (e.g. ipop)

@param ifname the name of the interface you want to return
'''
# needs fixing to return ip6
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


'''
Builds the graph of all the connections present in the network.
Uses the con_table to name each vertex and assigns an ip to each vertex.
The vm network is treated as a complete graph.
The function draws a graph an outputs it as a file.

@param fname, the file name for the output graph image
'''
def build_connection_graph(fname):
    # add vertices for all keys in con_table
    # this node is always the 0th vertex.
    if not fname:
        fname = "graph0.png"

    me = con_graph.vertex(0)
    v_name[me] = socket.gethostname()
    v_ip[me] = get_ip_address('ipop')

    for v,c in zip(con_graph.vertices(), con_table.iteritems()):
        if v_name[v] == "":
            v_name[v] = c[1]['name']
            v_ip[v] = c[1]['ip']
            v_uid[v] = c[1]['uid']
    graph_draw(con_graph, vertex_text=con_graph.vertex_index, vertex_font_size=18,\
            output_size=(400, 400), output=fname)

'''
Calculates the latencies of the edges between the paths by observing network traffic
Updates graph edge details in con_graph
'''
def calc_latency(): pass


class MC2Server(UdpServer):
    def __init__(self, user, password, host, ip4, uid):

        UdpServer.__init__(self, user, password, host, ip4)
        self.uid = uid
        self.peerlist = set()
        self.ip_map = dict(IP_MAP)
        self.hop_count = CONFIG['multihop_cl'] -  CONFIG['multihop_ihc']
        
        # this dict stores the local user state
        self.state = {}

        # this dict store the state for each peer
        self.peers = {}

        # this set keeps track of unique
        self.peerlist = set()

        # this creates the UDP socket for communication with tincan
        if socket.has_ipv6:
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 0))

        # creates a random 20-byte uid and translates it to a hex string
        uid = binascii.b2a_hex(os.urandom(CONFIG["uid_size"]/2))

        # enables logging
        do_set_logging(self.sock, CONFIG["tincan_logging"])

        # sets the callback in tincan in order to receive event notifications
        do_set_cb_endpoint(self.sock, self.sock.getsockname())

        # configures the ipop interface and sets uid for XMPP network
        do_set_local_ip(self.sock, uid, ip4, gen_ip6(uid), CONFIG["ip4_mask"],
            CONFIG["ip6_mask"], CONFIG["subnet_mask"])

        # connects to XMPP service
        do_register_service(self.sock, user, password, host)

        # requests tincan to get state
        do_get_state(self.sock, False)

        do_set_translation(self.sock, 1)

        if CONFIG["icc"]:
            self.inter_controller_conn()
            self.lookup_req = {}
        if "network_ignore_list" in CONFIG:
            logging.debug("network ignore list")
            make_call(self.sock, m="set_network_ignore_list",\
                             network_ignore_list=CONFIG["network_ignore_list"])


    def create_connection(self, uid, data, overlay_id, sec, cas, ip4):
        # keeps track of unique peers
        self.peerlist.add(uid)

        # creates a new connection to a peer
        do_create_link(self.sock, uid, data, overlay_id, sec, cas)

        # assigns an ip address to a remote peer
        do_set_remote_ip(self.sock, uid, ip4, gen_ip6(uid))



    def set_far_peers(self):
        # for each peer in
        logging.debug("         PEERLIST            ")
        for p, v in self.peerlist:
            logging.debug("peer: %s", p)
            logging.debug("value: %s", v)

            # choose a random path or length hop count
            # that does not include the peer
            # the source or dest.
            # set this in the far peers table
        logging.debug("%s", self.peerlist)
        
        logging.debug("         PEERS            ")
        for p, v in self.peers:
            logging.debug("peer: %s", p)
            logging.debug("value: %s", v)

            # choose a random path or length hop count
            # that does not include the peer
            # the source or dest.
            # set this in the far peers table
        logging.debug("%s", self.peers)


    def trim_connections(self):
        # this function is called about every 30 seconds and deletes
        # offline connections, it is important to delete old connections
        # because tincan will not allow reconnections if old connections
        # are still around
        for k, v in self.peers.iteritems():
            if "fpr" in v and v["status"] == "offline":
                if v["last_time"] > CONFIG["wait_time"] * 2:
                    do_trim_link(self.sock, k)

    def serve(self):
        # waits for incoming connections
        socks = select.select([self.sock], [], [], CONFIG["wait_time"])
        for sock in socks[0]:
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
                    
                    #ECHO REQUEST MESSAGE
                    if msg_type == "echo_request":
                        make_remote_call(self.sock_svr, m_type=tincan_control,\
                          dest_addr=addr[0], dest_port=addr[1], payload=None,\
                          type="echo_reply")
                          
                    #LOCAL STATE MESSAGE
                    if msg_type == "local_state":
                        self.state = msg
                    
                    #PEER STATE MESSAGE
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
                    
                    #CONNECT REQUEST MESSAGE 
                    elif msg_type == "con_req": 
                        if CONFIG["on-demand_connection"]: 
                            self.idle_peers[msg["uid"]]=msg
                        else:
                            if self.check_collision(msg_type,msg["uid"]): 
                                continue
                            fpr_len = len(self.state["_fpr"])
                            fpr = msg["data"][:fpr_len]
                            cas = msg["data"][fpr_len + 1:]
                            ip4 = self.uid_ip_table[msg["uid"]]
                            self.create_connection(msg["uid"], fpr, 1, 
                                                   CONFIG["sec"], cas, ip4)
                    elif msg_type == "con_resp":
                        if self.check_collision(msg_type, msg["uid"]): continue
                        fpr_len = len(self.state["_fpr"])
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
                
                    src_uid = data[2:22]
                    dest_uid = data[22:42]
                    src_mac = data[42:48]
                    dest_mac = data[58:54]

                    #Ignore IPv6 packets for log readability. Most of them are 
                    #Multicast DNS packets
                    if data[54:56] == "\x86\xdd":
                        continue
                    logging.debug("IP packet forwarded \nversion:{0}\nmsg_type:"
                        "{1}\nsrc_uid:{2}\ndest_uid:{3}\nsrc_mac:{4}\ndst_mac:{"
                        "5}\neth_type:{6}".format(data[0].encode("hex"), \
                        data[1].encode("hex"), data[2:22].encode("hex"), \
                        data[22:42].encode("hex"), data[42:48].encode("hex"),\
                        data[48:54].encode("hex"), data[54:56].encode("hex")))

                    if data[54:56] == "\x08\x06": #ARP Message
                        if CONFIG["switchmode"]:
                            self.arp_handle(data)
                        continue

                    if data[54:56] == "\x08\x00": #IPv4 Packet
                        if CONFIG["switchmode"]:
                        
                            vistited.add(src_uid)
                            
                            dest = random.choice(peerlist)
                            
                            while dest == self.uid or dest in visited:
                                dest = random.choice(peerlist)
                                
                            #WRAP
                            tmp_data[0] = ipop_ver
                            tmp_data[1] = mcvpn_packet
                            tmp_data[2:22] = self.uid
                            tmp_data[22:42] = dest
                            tmp_data[42:48] = mac_a2b(self.state["_mac"]) 
                            tmp_data[48:54] = mac_a2b(self.peers[dest]["mac"])
                            tmp_data[54:56] = data[54:56]
                            tmp_data[56:] = data[42:]
                            
                            self.packet_handle(data, mcvpn_packet)
                        continue

                    if not CONFIG["on-demand_connection"]:
                        continue
                    if len(data) < 16:
                        continue
                    self.create_connection_req(data[2:])
                    
                elif data[1] == mcvpn_packet:
                    continue
                    print "THIS IS AN MCVPN PACKET ",
                    print data

                    #AM I HERE?
                    if self.uid == dest_uid:
                        
                    #PEEL
                    data = data[42:]
    
                else:
                    logging.error("Unknown type message")
                    logging.debug("{0}".format(data[0:].encode("hex")))
                    sys.exit()

            elif sock == self.cc_sock:
                data, addr = sock.recvfrom(CONFIG["buf_size"])
                logging.debug("ICC packet received from {0}".format(addr))
                self.icc_packet_handle(data)
                
            else:
                logging.error("Unknown type socket")
                sys.exit()


    def multihop_server(self, data):

        # |-------------------------------------------------------------|
        # | offset(byte) |                                              |
        # |-------------------------------------------------------------|
        # |      0       | ipop version                                 |
        # |      1       | message type                                 |
        # |      2       | source uid                                   |
        # |     22       | destination uid                              |
        # |     42       | Payload (Ethernet frame)                     |
        # |-------------------------------------------------------------|

        self.multihop_handle(data)
        dest_ip6=ip6_b2a(data[80:96])
        logging.debug("dest_ip6 %s", dest_ip6)

        target_ip6=ip6_b2a(data[40:56])
        logging.pktdump("Multihop Packet Destined to {0}".format(target_ip6))

        if data[1] == tincan_sr6:
            # do something different for this msg type
            # since this packet has already had a path
            # attached to its  payload we don't need to
            # assign a new path for this packet.

            # Remove the first address in payload path
            # call make remote call to send the remainder
            # of the payload packet to the next hop in the
            # path.

            logging.pktdump("Multihop packet received in Multihop Server.", dump=data)
            hop_index = ord(data[2]) + 1
            hop_count = ord(data[3])
            if hop_index == hop_count:
                do_set_remote_ip(self.sock, uid, ip4, gen_ip6(uid))
                make_call(self.sock, payload=null_uid + null_uid +\
                  data[4+(hop_index)*16:])
                return True
            packet = chr(hop_index)
            packet += data[3:]
            next_addr_offset = 4+(hop_index)*16
            next_hop_addr = data[next_addr_offset:next_addr_offset+16]

            for k, v in self.peers.iteritems():
                if v["ip6"]==ip6_b2a(next_hop_addr) and v["status"]=="online":

                    make_remote_call(sock=self.cc_sock,\
                      dest_addr=ip6_b2a(next_hop_addr),\
                      dest_port=CONFIG["icc_port"], m_type=tincan_sr6,\
                      payload=packet)
                    return True
            via = []

            for i in range(hop_count):
                via.append(ip6_b2a(data[4+i*16:4+16*i+16]))

            make_remote_call(sock=self.cc_sock, dest_addr=via[hop_index-2],\
              dest_port=CONFIG["icc_port"], m_type=tincan_control,\
              payload=None, msg_type="route_error", via=via, index=hop_index-2)

            logging.debug("Link lost send back route_error message to source{0}"
                          "".format(via[hop_index-2]))
            return False


        # else this packet needs a new path in our system
        # and we should calculate one.
        elif dest_ip6 in self.peers_ip6:
            logging.pktdump("Destination({0}) packet is in"
                  "peers_ip6({1})".format(dest_ip6, self.far_peers))

            if CONFIG["multihop_sr"]: # Source routing
                # Attach all the ipv6 address of hop in the
                payload = tincan_sr6 # Multihop packet
                payload = "\x01" # Hop Index
                payload += chr(self.hop_count+1) # Hop Count

                # GET NEW PATH
                paths = self.gen_new_path(dest_ip6)
                # ADD PATH HOPS TO PAYLOAD
                for hop in paths:
                    logging.debug ( "%s", hop )
                    payload += ip6_a2b(hop)
                payload += data[80:96]
                payload += data[42:]

                # send packet to the next hop
                logging.pktdump("sending", dump=payload)

                do_set_remote_ip(self.sock, uid, ip4, gen_ip6(uid))

                make_remote_call(sock=self.sock,\
                  dest_addr=paths[0][0],\
                  dest_port=CONFIG["svpn_port"],\
                  m_type=tincan_sr6, payload=payload)
                logging.debug("TRUE OUT MULTIHOP SERVER")
                return True
            else:
                # Non source route mode
                do_set_remote_ip(self.sock, uid, ip4, gen_ip6(uid))
                make_remote_call(sock=self.cc_sock, \
                  dest_addr=self.peers_ip6[dest_ip6],\
                  dest_port=CONFIG["svpn_port"],\
                  m_type=tincan_packet, payload=data[42:])
                logging.debug("TRUE OUT MULTIHOP SERVER")
                return True
        else: pass
            # dest_ip6 not found in self.peers
            # logging.debug ( "dest_ip6 not found in self.peers" )
            # Destination is not known, we flood lookup_req msg
            # self.lookup(dest_ip6)
            # self.create_connection(msg["uid"], fpr, 1,CONFIG["sec"], cas, ip4)

            # return False
        return False
    '''
    Wrapper for find_path. Fixes max and min latency vars.

    @returns a randomly chosen path.
    '''
    def gen_new_path(self, dest):
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

    '''
    Generates a new random path from the source (this vm) to the destination vm
    within the required latency bounds

    @param max The maximum allowed latency
    @param min The minimum allowed latency
    @param dest The destination vm

    @return the new path paths
    '''
    def find_path(self, max, min, dest):
    
        logging.debug("             FIND PATH                ")
        
        # this line makes it so that our max hop count
        # is no greater than the number of peers in our cloud.
        if hop_count > len(self.peers_ip6):
            hop_count = len(self.peers_ip6)
        else:
             # get required number of hops
            hop_count = HOP_COUNT

        logging.debug ( "               HOP_COUNT = %s              ", hop_count )
        
         paths = []

        if hop_count == 0:
            # make hop final destination
            if dest in self.peers_ip6:
                logging.debug("0 HOP - FOUND DEST IN PEERS LIST")
                paths.append(self.peers_ip6(dest)) # final dest
                return paths

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
        # | therefore for the sake of simplicity we shall use hop_count number of random paths.                  |
        # | The feasibility study and implementation of the aforementioned algorithm shall be future work.       |
        # |______________________________________________________________________________________________________|
        # add hop count random elements from ip6_set
        # make hop_count random samples of length hop_count
        # and append that set into paths.
        # see above is hop_count is greater than peers_ip6

        for i in range(0, hop_count):
            paths.append(random.sample(self.peers_ip6, hop_count))

        # choose a set of random vertices equal to the hop_count
        '''
        This section is for illustrative purposes
        v = g.vertex(randint(0, g.num_vertices()))
        for i in range(1,hop_count-1):
            new_v = con_graph.vertex(randint(0, con_graph.num_vertices()))
            total_latency += edge_latency[con_graph.edge(0,new_v)]
            while path.contains(new_v) || total_latency > max:
                total_latency -= edge_latency[con_graph.edge(0,new_v)]
                new_v = con_graph.vertex(randint(0, con_graph.num_vertices()))
                total_latency += edge_latency[con_graph.edge(0,new_v)
            path.append(new_v)
        path.append(dest)
        '''
        logging.debug( "PATHS = %s",  paths )
        # make rpc call to send path chosen back to the xmppp server
        # rpc(...)
        return paths

def main():
    parse_config()
    server = MC2Server(CONFIG["xmpp_username"], CONFIG["xmpp_password"],
                       CONFIG["xmpp_host"], CONFIG["ip4"], CONFIG["local_uid"])
    last_time = time.time()
    #build_connection_graph(None)
    while True:
        server.serve()
        time_diff = time.time() - last_time
        if time_diff > CONFIG["wait_time"]:
            server.trim_connections()
            do_get_state(server.sock, False)
            last_time = time.time()

if __name__ == "__main__":
    main()
