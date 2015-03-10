#!/usr/bin/env python

from ipoplib2 import *
import socket
import fcntl
import struct
import itertools
import os



def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

# Gets the ip address of the specified interface (e.g. ipop)
# @param ifname the name of the interface you want to return
# needs fixing to return ip6

def get_ip_address(ifname):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  return socket.inet_ntoa(fcntl.ioctl(
      s.fileno(),
      0x8915,  # SIOCGIFADDR
      struct.pack('256s', ifname[:15])
  )[20:24])

# Helper function to parse ETH_P_ALL packets
#

def parse(packet):
  
  paresed_packet = {}
  packet, addr = packet
  data = packet

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
    # logging.debug("Not an Ethernet Packet")
    return None 

# Calculates the latencies of the edges between the paths by observing network traffic
# Updates graph edge details in con_graph

def calc_latency(): pass

class MC2Server(UdpServer):
    def __init__(self, user, password, host, ip4, uid):
      UdpServer.__init__(self, user, password, host, ip4)
      self.idle_peers = {}
      self.user = user
      self.password = password
      self.host = host
      self.ip4 = ip4
      self.uid = gen_uid(ip4)
      self.hop_count = CONFIG['multihop_cl'] -  CONFIG['multihop_ihc']
      self.ctrl_conn_init()

      # this set keeps track of unique peers
      self.peerlist = set()

      self.uid_ip_table = {}

      #do_set_translation(self.sock, 1)

      parts = CONFIG["ip4"].split(".")
      ip_prefix = parts[0] + "." + parts[1] + "."

      for i in range(0, 255):
          for j in range(0, 255):
              ip = ip_prefix + str(i) + "." + str(j)
              uid = gen_uid(ip)
              self.uid_ip_table[uid] = ip

      if CONFIG["icc"]:
          self.inter_controller_conn()
          self.lookup_req = {}

      if CONFIG["switchmode"]:
          self.arp_table = {}

      if "network_ignore_list" in CONFIG:
          logging.debug("network ignore list")
          make_call(self.sock, m="set_network_ignore_list",\
                           network_ignore_list=CONFIG["network_ignore_list"])

    def ctrl_conn_init(self):
        # enables logging
        do_set_logging(self.sock, CONFIG["tincan_logging"])
        # sets the callback in tincan in order to receive event notifications
        do_set_cb_endpoint(self.sock, self.sock.getsockname())

        # configures the ipop interface and sets uid for XMPP network
        if not CONFIG["router_mode"]:
            do_set_local_ip(self.sock, self.uid, self.ip4, gen_ip6(self.uid),
                             CONFIG["ip4_mask"], CONFIG["ip6_mask"],
                             CONFIG["subnet_mask"])
        else:
            do_set_local_ip(self.sock, self.uid, CONFIG["router_ip"],
                           gen_ip6(self.uid), CONFIG["router_ip4_mask"],
                           CONFIG["router_ip6_mask"], CONFIG["subnet_mask"])

        # connects to XMPP service
        do_register_service(self.sock, self.user, self.password, self.host)
        do_set_switchmode(self.sock, CONFIG["switchmode"])
        do_set_trimpolicy(self.sock, CONFIG["trim_enabled"])
        # requests tincan to get state
        do_get_state(self.sock)

    def trim_connections(self):

        for k, v in self.peers.iteritems():
            if "fpr" in v and v["status"] == "offline":
                if v["last_time"] > CONFIG["wait_time"] * 2:
                    do_send_msg(self.sock, "send_msg", 1, k,
                                "destroy" + self.state["_uid"])
                    do_trim_link(self.sock, k)
            if CONFIG["on-demand_connection"] and v["status"] == "online":
                if v["last_active"] + CONFIG["on-demand_inactive_timeout"]\
                                                              < time.time():
                    logging.debug("Inactive, trimming node:{0}".format(k))
                    do_send_msg(self.sock, 1, "send_msg", k,
                                "destroy" + self.state["_uid"])
                    do_trim_link(self.sock, k)

    def ondemand_create_connection(self, uid, send_req):
        logging.debug("idle peers {0}".format(self.idle_peers))
        peer = self.idle_peers[uid]
        fpr_len = len(self.state["_fpr"])
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

    def create_connection(self, uid, data, nid, sec, cas, ip4):
        # keeps track of unique peers
        self.peerlist.add(uid)
        do_create_link(self.sock, uid, data, nid, sec, cas)
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
    
    def wrap(self, route, packet):
        
      for r in route:
          packet = r + packet
            
      return packet

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
        logging.debug("             FIND PATH                ")

        # this line makes it so that our max hop count
        # is no greater than the number of peers in our cloud.
        if hop_count > len(self.peers):
            hop_count = len(self.peers)

        logging.debug ( "               HOP_COUNT = %s              ", hop_count )
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
        logging.debug(self.peers[guest_uid])

        if dest in self.peers && self.peers[guest_uid]['status'] == 'online':
          for i in range(0, hop_count):
              paths.append(random.sample(self.peers, hop_count))

        logging.debug( "PATHS = %s",  paths )
        # make rpc call to send path chosen back to the xmppp server
        # rpc(...)
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
      # logging.debug( "Local Packet Found!" )
      route = self.calc_route(source, dest)
      if not(route):
          # no viable route to packet
          # handle packet directly
          # do nothing
          return None

      else:
        logging.debug("route = %s", route)
        packet = self.wrap(route, packet)
        #next_hop_addr = route[len(route)-1] 
        make_remote_call(self.sock, d_addr, CONFIG['svpn_port'], tincan_packet, packet)
        logging.debug( "Local Packet Route Calculated and Sent!" )

      return

    def local_serve(self, sock):
        # waits for incoming connections
        # logging.debug( "       LOCAL SERVE         " )
        if sock == self.sock_udp:
            packet = sock.recvfrom(CONFIG["buf_size"])
            parsed_packet = parse(packet)

            if(parsed_packet and parsed_packet['data'][0] not in control_packet_types):
              # If this packet's src addr is the same as the
              # config address then this packet originates
              # from the local machine. We should introduce
              # logic to handle the routing of this packet.
              if str(parsed_packet["source"]) == CONFIG['ip4']:
                  self.local_packet_handle(parsed_packet["source"], parsed_packet["dest"], parsed_packet["data"])



    def serve(self):
        # waits for incoming connections
        socks, _, _ = select.select( self.sock_list, [], [], CONFIG["wait_time"] )
        for sock in socks:
            # logging.debug("CONFIG[ip4] %s", CONFIG["ip4"])
            if sock == self.sock_udp:
                self.local_serve(sock)
                continue
            elif sock == self.sock or sock == self.sock_svr:
                
                # ---------------------------------------------------------------
                # | offset(byte) |                                              |
                # ---------------------------------------------------------------
                # |      0       | ipop version                                 |
                # |      1       | message type                                 |
                # |      2       | Payload (JSON formatted control message)     |
                # ---------------------------------------------------------------
                data, addr = sock.recvfrom(CONFIG["buf_size"])
                if data[0] != ipop_ver :
                    logging.debug("ipop version mismatch: tincan:{0} controller" \
                                    ":{1}" "".format(data[0].encode("hex"), \
                                    ipop_ver.encode("hex")))
                    sys.exit()
                elif data[1] == tincan_control:
                    logging.debug( "        TINCAN CONTROL        " )
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
                    logging.debug( "        TINCAN PACKET 0       " )
                    #Ignore IPv6 packets for log readability. Most of them are 
                    #Multicast DNS packets
                    if data[54:56] == "\x86\xdd":
                        # logging.debug( "        TINCAN PACKET  1      " )
                        continue

                    logging.debug("IP packet forwarded \nversion:{0}\nmsg_type:"
                        "{1}\nsrc_uid:{2}\ndest_uid:{3}\nsrc_mac:{4}\ndst_mac:{"
                        "5}\neth_type:{6}".format(data[0].encode("hex"), \
                        data[1].encode("hex"), data[2:22].encode("hex"), \
                        data[22:42].encode("hex"), data[42:48].encode("hex"),\
                        data[48:54].encode("hex"), data[54:56].encode("hex")))

                    if data[54:56] == "\x08\x06": #ARP Message
                        logging.debug( "        TINCAN PACKET  2      " )
                        if CONFIG["switchmode"]:
                            self.arp_handle(data)
                        continue

                    if data[54:56] == "\x08\x00": #IPv4 Packet
                        logging.debug( "        TINCAN PACKET  3      " )
                        if CONFIG["switchmode"]:
                            logging.debug("Sending to self.packet_handle(data)")
                            self.packet_handle(data)
                        continue







                    if not CONFIG["on-demand_connection"]:
                        logging.debug( "        TINCAN PACKET  4      " )
                        continue
                    if len(data) < 16:
                        logging.debug( "        TINCAN PACKET  5      " )
                        continue
                    logging.debug( "        TINCAN PACKET  6      " )
                    self.create_connection_req(data[2:])



                    # src_uid = data[2:22]
                    # dest_uid = data[22:42]
                    # src_mac = data[42:48]
                    # dest_mac = data[58:54]

                    # #Ignore IPv6 packets for log readability. Most of them are
                    # #Multicast DNS packets
                    # if data[54:56] == "\x86\xdd":
                    #     continue
                    # logging.debug("IP packet forwarded \nversion:{0}\nmsg_type:"
                    #     "{1}\nsrc_uid:{2}\ndest_uid:{3}\nsrc_mac:{4}\ndst_mac:{"
                    #     "5}\neth_type:{6}".format(data[0].encode("hex"), \
                    #     data[1].encode("hex"), data[2:22].encode("hex"), \
                    #     data[22:42].encode("hex"), data[42:48].encode("hex"),\
                    #     data[48:54].encode("hex"), data[54:56].encode("hex")))

                    # if data[54:56] == "\x08\x06": #ARP Message
                    #     if CONFIG["switchmode"]:
                    #         self.arp_handle(data)
                    #     continue

                    # if data[54:56] == "\x08\x00": #IPv4 Packet
                    #     if CONFIG["switchmode"]:

                    #         vistited.add(src_uid)

                    #         dest = random.choice(peerlist)

                    #         while dest == self.uid or dest in visited:
                    #             dest = random.choice(peerlist)

                    #         #WRAP
                    #         tmp_data[0] = ipop_ver
                    #         tmp_data[1] = mcvpn_packet
                    #         tmp_data[2:22] = self.uid
                    #         tmp_data[22:42] = dest
                    #         tmp_data[42:48] = mac_a2b(self.state["_mac"])
                    #         tmp_data[48:54] = mac_a2b(self.peers[dest]["mac"])
                    #         tmp_data[54:56] = data[54:56]
                    #         tmp_data[56:] = data[42:]

                    #         self.packet_handle(data, mcvpn_packet)
                    #     continue

                    # if not CONFIG["on-demand_connection"]:
                    #     continue
                    # if len(data) < 16:
                    #     continue
                    # self.create_connection_req(data[2:])

                elif data[1] == mcvpn_packet:
                    continue
                    print "THIS IS AN MCVPN PACKET ",
                    print data

                    #AM I HERE?
                    #if self.uid == dest_uid:


                    #PEEL
                    data = data[42:]

                else:
                  # pass
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

    
    
def main():
    parse_config()
    server = MC2Server(CONFIG["xmpp_username"], CONFIG["xmpp_password"],
                       CONFIG["xmpp_host"], CONFIG["ip4"], CONFIG["local_uid"])
    last_time = time.time()
    while True:
        #fork
        # newpid = os.fork()
        # if newpid == 0:
        #     server.local_serve()
        # else:
        server.serve()
        
        time_diff = time.time() - last_time
        if time_diff > CONFIG["wait_time"]:
            server.trim_connections()
            do_get_state(server.sock, False)
            last_time = time.time()

        # if raw_input( ) == 'q': break

if __name__ == "__main__":
    main()
