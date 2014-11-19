#!/usr/bin/env python

import getpass
import hashlib
import json
import logging
import random
import select
import socket 
import struct
import sys
import time

CONFIG = dict()

def gen_uid(ip4):
    return hashlib.sha1(ip4).hexdigest()[:CONFIG['uid_size']]

def gen_ip6(uid, ip6=None):
    if ip6 is None:
        ip6 = CONFIG["ip6_prefix"]
    for i in range(0, 16, 4): 
        ip6 += ":" + uid[i:i + 4]
    return ip6

def rpc(sock, **params):
    ipaddr = CONFIG['localhost6'] if socket.has_ipv6 else CONFIG['localhost'] 
    return sock.sendto(json.dumps(params), (ipaddr, CONFIG['rpc_port']))

def rpc_send_msg(sock, overlay_id, uid, data):
    # DEBUG logging messages
    logging.debug('--> rpc_send_msg')
    logging.debug('    uid: %s', uid)
    logging.debug('    data: %s', data[:25])
    # ----------------------------------------
    return rpc(sock, m='send_msg', overlay_id=overlay_id, uid=uid, data=data)

def rpc_set_cb_endpoint(sock, addr):
    # DEBUG logging messages
    logging.debug('--> rpc_set_cb_endpoint')
    logging.debug('    addr: %s', addr)
    # ----------------------------------------
    return rpc(sock, m='set_cb_endpoint', ip=addr[0], port=addr[1])

def rpc_register_service(sock, username, password, host):
    # DEBUG logging messages
    logging.debug('--> rpc_register_service')
    logging.debug('    host: %s', host)
    logging.debug('    username: %s', username)
    logging.debug('    password: %s', password)
    # ----------------------------------------
    return rpc(sock, m='register_service', username=username, password=password, host=host)

def rpc_create_link(sock, uid, fpr, overlay_id, sec, cas, stun=None, turn=None):
    # DEBUG logging messages
    logging.debug('--> rpc_create_link')
    logging.debug('    uid: %s', uid)
    logging.debug('    cas: %s', cas[:25])
    # ----------------------------------------
    if stun is None: stun = random.choice(CONFIG['stun'])
    if turn is None: turn = random.choice(CONFIG['turn']) if CONFIG['turn'] else {'server': '', 'user': '', 'pass': ''}
    return rpc(sock, m='create_link', uid=uid, fpr=fpr, overlay_id=overlay_id, stun=stun, turn=turn['server'], turn_user=turn['user'], turn_pass=turn['pass'], sec=sec, cas=cas)

def rpc_trim_link(sock, uid):
    # DEBUG logging messages
    logging.debug('--> rpc_trim_link')
    logging.debug('    uid: %s', uid)
    # ----------------------------------------
    return rpc(sock, m='trim_link', uid=uid)

def rpc_set_local_ip(sock, uid, ip4, ip6, ip4_mask, ip6_mask, subnet_mask):
    # DEBUG logging messages
    logging.debug('--> rpc_set_local_ip')
    logging.debug('    uid: %s', uid)
    logging.debug('    IPv4: %s', ip4)
    logging.debug('    mask: %s', ip4_mask)
    logging.debug('    IPv6: %s', ip6)
    logging.debug('    mask: %s', ip6_mask)
    logging.debug('    subm: %s', subnet_mask)
    # ----------------------------------------
    return rpc(sock, m='set_local_ip', uid=uid, ip4=ip4, ip6=ip6, ip4_mask=ip4_mask, ip6_mask=ip6_mask, subnet_mask=subnet_mask)

def rpc_set_remote_ip(sock, uid, ip4, ip6):
    # DEBUG logging messages
    logging.debug('--> rpc_set_remote_ip')
    logging.debug('    uid: %s', uid)
    logging.debug('    IPv4: %s', ip4)
    logging.debug('    IPv6: %s', ip6)
    # ----------------------------------------
    return rpc(sock, m='set_remote_ip', uid=uid, ip4=ip4, ip6=ip6)

def rpc_get_state(sock):
    # DEBUG logging messages
    logging.debug('--> rpc_get_state')
    # ----------------------------------------
    return rpc(sock, m='get_state')

def rpc_set_logging(sock, tincan_logging_level):
    logging.debug('--> rpc_set_logging')
    logging.debug('    val: %s', tincan_logging_level)
    return rpc(sock, m='set_logging', logging=tincan_logging_level)

class MigrationState: Migrating, Reconnecting, NoOp = range(3)

class UdpServer:
    def __init__(self, user, password, host, ip4):
        self.state = {}
        self.peers = {}
        self.user = user
        self.password = password
        self.host = host
        self.ip4 = ip4
        self.uid = gen_uid(ip4)
        self.tincan_socket = socket.socket(socket.AF_INET6 if socket.has_ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
        '''
        Bind socket to any IP address the machine happens to have at any free port number.
        The port number assigned by the kernel among free ports above 1024.
        The actual assignment is available by calling sock.getsockname(). 
        '''
        self.tincan_socket.bind(('', 0))
        self.nova_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        '''
        Accept connections from any host on the notifications port.
        '''
        self.nova_socket.bind((CONFIG['nova_ip'], CONFIG['notifications_port']))
        self.mig_state = MigrationState.NoOp
        self.ranked_peers = []  # uid
        self.pending_con_reqs = {}  # uid -> con_req
        self.ctrl_conn_init()
        self.uid_ip_table = {}
        parts = CONFIG['ip4'].split('.')
        ip_prefix = parts[0] + '.' + parts[1] + '.'
        for i in range(0, 255):
            for j in range(0, 255):
                ip = ip_prefix + str(i) + '.' + str(j)
                uid = gen_uid(ip)
                self.uid_ip_table[uid] = ip

    def ctrl_conn_init(self):
        rpc_set_logging(self.tincan_socket, CONFIG['tincan_logging'])
        rpc_set_cb_endpoint(self.tincan_socket, self.tincan_socket.getsockname())
        rpc_set_local_ip(self.tincan_socket, self.uid, self.ip4, gen_ip6(self.uid), CONFIG['ip4_mask'], CONFIG["ip6_mask"], CONFIG['subnet_mask'])
        rpc_register_service(self.tincan_socket, self.user, self.password, self.host)
        rpc_get_state(self.tincan_socket)

    def create_connection(self, uid, data, nid, sec, cas, ip4):
        rpc_create_link(self.tincan_socket, uid, data, nid, sec, cas)
        rpc_set_remote_ip(self.tincan_socket, uid, ip4, gen_ip6(uid))

    def get_msg_fpr(self, msg):
        fpr_len = len(self.state['_fpr'])
        return msg['data'][:fpr_len]

    def get_msg_cas(self, msg):
        fpr_len = len(self.state['_fpr'])
        return msg['data'][fpr_len + 1:]

    def get_msg_uid(self, msg):
        return msg['uid']

    def get_ip4(self, uid):
        return self.uid_ip_table[uid]

    def process_con_req(self, msg):
        uid = self.get_msg_uid(msg)
        self.create_connection(uid, self.get_msg_fpr(msg), 1, CONFIG['sec'], self.get_msg_cas(msg), self.get_ip4(uid))

    def drop_connection(self, uid, msg=''):
        '''
        Drops a connection to the peer with the given uid and optionally logs a debug message.
        '''
        if len(msg) > 0:
            logging.debug(msg)
        rpc_send_msg(self.tincan_socket, 1, uid, 'destroy' + self.state['_uid'])
        rpc_trim_link(self.tincan_socket, uid)

    def trim_connections(self):
        timeout = CONFIG['wait_time'] * (2 if (self.mig_state == MigrationState.NoOp) else 5)  
        for uid, attrs in self.peers.iteritems():
            time_offline = time.time() - attrs['last_active']
            if 'fpr' in attrs and attrs['status'] == 'offline' and time_offline > timeout:
                self.drop_connection(uid, '--> trimming offline node %s' % self.uid_ip_table[uid])

    def drop_all_connections(self):
        '''
        Drops all connections to peers.
        '''
        # DEBUG logging messages
        logging.debug('--- dropping all connections')
        # ----------------------------------------
        for uid in self.peers.keys():
            self.drop_connection(uid)

    def calculate_window_traffic(self, window_size):
        peer_window_traffic = []
        if len(self.peers) == 0:
            return []
        for uid, attrs in self.peers.iteritems():
            if attrs['status'] == 'offline':
                continue
            traffic = attrs['traffic']
            index = min(window_size, len(traffic)) - 1 
            bytes_in_window = traffic[0] - traffic[index]
            '''
            Tuples in the peer_window_traffic list are 'reversed' for efficiency.
            Having the traffic data as the first element takes advantage of the DSU
            idiom without actually incurring any extra cost.
            '''
            peer_window_traffic.append((bytes_in_window, uid))
        return peer_window_traffic

    def calculate_window_size(self):
        target_volume = 1048576 # 1 MB
        size = CONFIG['traffic_window_size']
        for uid, attrs in self.peers.iteritems():
            if attrs['status'] == 'offline':
                continue
            traffic = attrs['traffic']
            hist_length = len(traffic) 
            while hist_length > size and (traffic[0] - traffic[size]) < target_volume:
                size += 1
        return size

    def rank_peers(self):
        '''
        Returns a list of peers sorted in descending order of relevance.
        
        The relevance of a peer is defined by the amount of traffic this node
        has exchanged through the link with the peer in the recent past.
        The recent past is defined by the window_size argument.
        '''
        window_size = self.calculate_window_size()
        peer_window_traffic = self.calculate_window_traffic(window_size)
        if len(peer_window_traffic) == 0:
            return []
        '''
        Sort the list by bytes transmitted over each link within the window
        and reverse it in order to get a descending list.
        '''
        peer_window_traffic.sort(reverse=True)
        self.ranked_peers = [pt[1] for pt in peer_window_traffic]
        # DEBUG logging messages  
        logging.debug('--- ranked peers:')
        logging.debug('    %s', ', '.join([self.uid_ip_table[p] for p in self.ranked_peers]))
        # ----------------------------------------

    def notify_ready_to_migrate(self, ipaddr, port):
        notif_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        notif_socket.connect((ipaddr, port))
        msg = {'type':'migration_confirmation', 'status':'ready'}
        notif_socket.sendall(json.dumps(msg))
        notif_socket.close()  

    def serve(self):
        '''
        Listens for incoming connections on ...
        '''
        in_socks = [self.nova_socket, self.tincan_socket]
        ins, outs, errors = select.select(in_socks, [], [], CONFIG['wait_time']) # this is a blocking call
        for ready_sock in ins:
            data, addr = ready_sock.recvfrom(CONFIG['buf_size'])
            #ipaddr = addr[0]
            #port = addr[1]
            if data[0] == '{':
                msg = json.loads(data)
                msg_type = msg.get('type', None)
                # process different types of notifications
                if msg_type == 'migration_state':
                    if msg['status'] == 'initiating':
                        logging.info('Preparing for migration.')
                        self.mig_state = MigrationState.Migrating
                        self.drop_all_connections()
                        self.rank_peers()
                        reply_addr, reply_port = msg['reply_address']
                        self.notify_ready_to_migrate(reply_addr, reply_port);
                        logging.info('Ready.')
                    elif msg['status'] == 'success':
                        logging.info('Migration successful. Reconnecting.')
                        rpc_register_service(self.tincan_socket, self.user, self.password, self.host)
                        self.mig_state = MigrationState.Reconnecting
                elif msg_type == 'local_state':
                    '''
                    This notification is sent to the controller as a result of the get_state() rpc.
                    It contains information about the local node.
                    '''
                    self.state = msg
                    # DEBUG logging messages
                    logging.debug('<-- local_state notif.')
                    logging.debug('    uid: %s', msg['_uid'])
                    logging.debug('    IPv4: %s', msg['_ip4'])
                    # ---------------------------------------- 
                elif msg_type == 'peer_state':
                    '''
                    This notification is sent to the controller as a result of the get_state() rpc.
                    It contains information about one peer node.
                    
                    Fields in msg:
                    uid        UID of the peer node
                    ip4        IPv4 of peer node
                    ip6        IPv6 of peer node
                    fpr        X.509 certificate fingerprint of peer node
                    status     online | offline (indicates whether the P2P connection is working)
                    security   none | dtls (indicates whether the P2P connection is encrypted)
                    stats      Colon-separated measurements of bytes sent over the P2P connection
                    stats_cons List of IP addresses of the endpoints used for each connection  
                    '''
                    '''
                    The traffic log consists of a list of byte counts representing the amount 
                    of information transmitted over the link up to the moment it was recorded.
                    Since measurements are taken at regular intervals, it is possible to
                    compute the amount of traffic for any given period of time.
                    The first count inserted in the list is always zero.
                    '''
                    if msg['uid'] in self.peers:
                        msg["last_active"] = self.peers[msg["uid"]]["last_active"]
                        msg['traffic'] = self.peers[msg['uid']]['traffic']
                    else:
                        msg["last_active"] = time.time()
                        msg['traffic'] = [0]
                    if msg['status'] == 'online':
                        # Calculate total number of bytes transmitted over the link
                        total_bytes = 0
                        stats = msg['stats'].split(' ')
                        for info in stats:
                            if len(info.split(':')) > 9:
                                total_bytes += int(info.split(':')[6]) + int(info.split(':')[8])
                    else:
                        total_bytes = msg['traffic'][0]
                    '''
                    Add an entry to the traffic log of a peer.
                    The latest byte count is always inserted at the front of the list.
                    '''
                    max_history = 720 # about one hour (60*60/5)
                    if len(msg['traffic']) == max_history: msg['traffic'].pop() # this is O(1) 
                    msg['traffic'].insert(0, total_bytes) # this is O(1)
                    if msg['traffic'][0] > msg['traffic'][1]:
                        msg['last_active'] = time.time()
                    self.peers[msg["uid"]] = msg
                    # DEBUG logging messages
                    logging.debug('<-- peer_state notif.:')
                    logging.debug('    IPv4: %s', msg['ip4'])
                    logging.debug('    Status: %s', msg['status'])
                    logging.debug('    Total bytes: %u', total_bytes)
                    # ----------------------------------------                    
                elif msg_type == 'con_stat':
                    '''
                    This notification is sent to the controller when a tincan P2P link changes state.
                    Current impl. ignores connection status notifications.
                    '''
                    pass
                elif msg_type == 'con_req':
                    '''
                    This notification is sent to the controller when a new node joins the network.
                    This notification represents the ping mechanism over XMPP, so it is also sent 
                    every 120 seconds.
                    '''
                    # DEBUG logging messages
                    logging.debug('<-- con_req notif.:')
                    logging.debug('    IPv4: %s', self.get_ip4(self.get_msg_uid(msg)))
                    logging.debug('    cas: %s...', self.get_msg_cas(msg)[:25])
                    # ----------------------------------------
                    if (self.mig_state == MigrationState.Migrating):
                        # discard request
                        continue
                    elif (self.mig_state == MigrationState.NoOp):
                        # regular operation; accept new connections
                        self.process_con_req(msg)
                    else:
                        '''
                        MigrationState.Reconnecting
                        Accept connections selectively based on a pre-computed priority
                        '''
                        uid = self.get_msg_uid(msg)
                        self.pending_con_reqs[uid] = msg
                        hpp = self.ranked_peers[0]  # highest priority peer
                        while (hpp in self.pending_con_reqs):
                            msg = self.pending_con_reqs.pop(hpp)
                            self.process_con_req(msg)
                            del self.ranked_peers[0]
                            hpp = self.ranked_peers[0] if len(self.ranked_peers) > 0 else None
                        '''
                        If we are done reconnecting to previous peers, update migration status and
                        process any request that might have arrived while reconnecting.
                        ''' 
                        if (len(self.ranked_peers) == 0):
                            self.mig_state = MigrationState.NoOp
                            logging.info('All pre-migration links recreated.')
                            for req in self.pending_con_reqs.values():
                                self.process_con_req(req)
                elif msg_type == 'con_resp':
                    '''
                    This notification is sent to the controller when a response to a con_req is received from a peer.
                    '''
                    # DEBUG logging messages
                    logging.debug('<-- con_resp notif.:')
                    logging.debug('    IPv4: %s', self.get_ip4(self.get_msg_uid(msg)))
                    logging.debug('    cas: %s...', self.get_msg_cas(msg)[:25])
                    # ----------------------------------------
                    self.process_con_req(msg)
                elif msg_type == 'send_msg':
                    '''
                    send message is used as 'request for start mutual connection'
                    '''
                    # DEBUG logging messages
                    logging.debug('<-- send_msg notif:')
                    logging.debug('    data: %s...', msg['data'][:25])
                    # ----------------------------------------
                    if msg['data'].startswith('destroy'):
                        rpc_trim_link(self.tincan_socket, msg['uid'])
            else:
                '''
                Packets addressed to nodes to which there is no P2P connection yet are forwarded to controller.
                Only for "on-demand" connections
                '''
                pass

def main():
    with open('config.json', mode='r') as f:
        loaded_config = json.load(f)
    CONFIG.update(loaded_config)
    logging.basicConfig(filename='controller.log', level=eval(CONFIG['controller_logging']), format='%(asctime)s %(levelname)8s %(message)s', datefmt='%m-%d %M:%S')
    server = UdpServer(CONFIG['xmpp_username'], CONFIG['xmpp_password'], CONFIG['xmpp_host'], CONFIG['ip4'])
    last_time = time.time()
    while True: # there is a blocking call in server.serve() 
        server.serve()
        time_diff = time.time() - last_time
        if time_diff > CONFIG['wait_time'] and server.mig_state != MigrationState.Migrating:
            server.trim_connections()
            rpc_get_state(server.tincan_socket)
            last_time = time.time()

if __name__ == '__main__':
    main()
