"""
Steven Portzer        
Start Date: 07/26/2012

Purpose: Match IP addresses.

"""

import posix_preprocessor
import ipaddr
import os.path



DEFAULT_IGNORE_ADDRS = [('127.0.0.1', 53)]

ENABLE_TCP_DATA_MATCHING = None


HOST_INFO = []
TRACE_INFO = {}
IGNORE_ADDRS = set()

tcp_sockets = set()
tcp_matches = set()



def initialize_hosts(config_filename, enable_tcp_data_matching):
  """
  Loads a configuration file that specifies a test to verify and returns
  a dictionary of preprocessed traces to feed into the model.
  """
  global ENABLE_TCP_DATA_MATCHING
  ENABLE_TCP_DATA_MATCHING = enable_tcp_data_matching

  for ip, port in DEFAULT_IGNORE_ADDRS:
    IGNORE_ADDRS.add((ipaddr.IPAddress(ip), port))

  base_dir = os.path.split(os.path.abspath(config_filename))[0]

  config_file = open(config_filename, 'r')
  trace_dict = {}
  trace_dict_copy = {}

  print "-" * 80
  print "Configuration"
  print "-" * 80

  host = -1

  for line in config_file:

    tokens = line.split()

    if not tokens:
      continue

    command = tokens[0].lower()
    tokens = tokens[1:]

    if command.startswith('#'):
      continue

    if command == 'ignore':
      if len(tokens) != 1:
        raise Exception("The 'ignore' command requires one argument")

      try:
        if "," in tokens[0]:
          ip, port = tokens[0].split(",", 1)
          port = int(port)
        else:
          ip = tokens[0]
          port = 0
        ip = ipaddr.IPAddress(ip)
        private_addr = (ip, port)
      except ValueError:
        raise Exception("'" + tokens[0] + "' is not a valid IP or IP,port")

      print "ignore", tokens[0]

      IGNORE_ADDRS.add((ip, port))

    elif command == 'host':
      host += 1

      if tokens:
        name = " ".join(tokens)
        print "host", name
      else:
        name = "host" + str(host)
        print "host"

      HOST_INFO.append({'name': name, 'ips': set(), 'nats': {}})

    elif host == -1 and command in ['trace', 'ip', 'nat']:
      raise Exception("The '" + command + "' must occur after a 'host' command")

    elif command == 'trace':
      if not tokens:
        raise Exception("The 'trace' command requires at least one argument")

      n = len(TRACE_INFO)
      trace_id = ""

      while n >= 0:
        trace_id = chr(ord('A') + n % 26) + trace_id
        n = n/26 - 1

      if len(tokens) < 2:
        name = "trace" + trace_id
        print " trace", trace_id, "(" + tokens[0] + ")"
      else:
        name = " ".join(tokens[1:])
        print " trace", trace_id + ":", name, "(" + tokens[0] + ")"

      filename = os.path.join(base_dir, tokens[0])

      trace = posix_preprocessor.get_trace_from_filename(filename)
      trace = posix_preprocessor.preprocess_trace(trace, trace_id)
      trace_dict[trace_id] = trace

      if ENABLE_TCP_DATA_MATCHING:
        trace_copy = posix_preprocessor.get_trace_from_filename(filename)
        trace_copy = posix_preprocessor.preprocess_trace(trace_copy, trace_id, False)
        trace_dict_copy[trace_id] = trace_copy

      TRACE_INFO[trace_id] = {'name': name, 'host': host, 'file': filename}

    elif command == 'ip':
      if len(tokens) != 1:
        raise Exception("The 'ip' command requires one argument")

      try:
        ip = ipaddr.IPAddress(tokens[0])
      except ValueError:
        raise Exception("'" + tokens[0] + "' is not a valid IP address")

      print " ip", tokens[0]

      HOST_INFO[host]['ips'].add(ip)

    elif command == 'nat':
      if len(tokens) != 2:
        raise Exception("The 'nat' command requires two argument")

      try:
        if "," in tokens[0]:
          ip, port = tokens[0].split(",", 1)
          port = int(port)
        else:
          ip = tokens[0]
          port = 0
        ip = ipaddr.IPAddress(ip)
        private_addr = (ip, port)
      except ValueError:
        raise Exception("'" + tokens[0] + "' is not a valid IP or IP,port")

      try:
        if "," in tokens[1]:
          ip, port = tokens[1].split(",", 1)
          port = int(port)
        else:
          ip = tokens[1]
          port = 0
        ip = ipaddr.IPAddress(ip)
        public_addr = (ip, port)
      except ValueError:
        raise Exception("'" + token[1] + "' is not a valid IP or IP,port")

      print " nat", tokens[0], "=>", tokens[1]

      HOST_INFO[host]['nats'].setdefault(public_addr, set()).add(private_addr)

    else:
      raise Exception("Unknown command '" + command + "'")

  print

  if ENABLE_TCP_DATA_MATCHING:
    find_tcp_matches(trace_dict_copy)

  config_file.close()
  return trace_dict



def initialize_unit_test(trace_filename_list, enable_tcp_data_matching):
  """
  Loads a list of trace files and initializes the network configuration
  based on the assumption that all traces were collected on the same
  host and that we don't need to specify any host IPs.
  """
  global ENABLE_TCP_DATA_MATCHING
  ENABLE_TCP_DATA_MATCHING = enable_tcp_data_matching

  for ip, port in DEFAULT_IGNORE_ADDRS:
    IGNORE_ADDRS.add((ipaddr.IPAddress(ip), port))

  trace_dict = {}
  trace_dict_copy = {}

  print "-" * 80
  print "Configuration"
  print "-" * 80
  print "host"
  HOST_INFO.append({'name': 'host0', 'ips': set(), 'nats': {}})

  for filename in trace_filename_list:

    n = len(TRACE_INFO)
    trace_id = ""

    while n >= 0:
      trace_id = chr(ord('A') + n % 26) + trace_id
      n = n/26 - 1

    name = "trace" + trace_id
    print " trace", trace_id, "(" + filename + ")"

    trace = posix_preprocessor.get_trace_from_filename(filename)
    trace = posix_preprocessor.preprocess_trace(trace, trace_id)
    trace_dict[trace_id] = trace

    if ENABLE_TCP_DATA_MATCHING:
      trace_copy = posix_preprocessor.get_trace_from_filename(filename)
      trace_copy = posix_preprocessor.preprocess_trace(trace_copy, trace_id, False)
      trace_dict_copy[trace_id] = trace_copy

    TRACE_INFO[trace_id] = {'name': name, 'host': 0, 'file': filename}

  print

  if ENABLE_TCP_DATA_MATCHING:
    find_tcp_matches(trace_dict_copy)

  return trace_dict
  


def find_tcp_matches(trace_dict):
  """
  Initializes TCP matches set with (connected socket, accepting socket)
  tuples for each pair of TCP sockets that look like a connection.
  """

  connect_sock_list = []
  accept_sock_list = []

  for trace_id in trace_dict:
    connect_socks, accept_socks = posix_preprocessor.get_sock_data(trace_id, trace_dict[trace_id])
    connect_sock_list.extend(connect_socks)
    accept_sock_list.extend(accept_socks)

  for connecting_sock in connect_sock_list:
    tcp_sockets.add(connecting_sock['name'])

  for accepting_sock in accept_sock_list:
    tcp_sockets.add(accepting_sock['name'])

  for connecting_sock in connect_sock_list:
    for accepting_sock in accept_sock_list:
      if connecting_sock['rcvlen'] > accepting_sock['sndlen'] or \
          accepting_sock['rcvlen'] > connecting_sock['sndlen']:
        continue

      length = min(connecting_sock['rcvlen'], accepting_sock['sndlen'])
      if connecting_sock['rcvbuf'][:length] != accepting_sock['sndbuf'][:length]:
        continue

      length = min(accepting_sock['rcvlen'], connecting_sock['sndlen'])
      if accepting_sock['rcvbuf'][:length] != connecting_sock['sndbuf'][:length]:
        continue

      tcp_matches.add((connecting_sock['name'], accepting_sock['name']))



def is_socket_match(connecting_sock, accepting_sock):
  """
  Returns True if the sockets look like they might form a connection.
  """

  if ENABLE_TCP_DATA_MATCHING:
    return (connecting_sock, accepting_sock) in tcp_matches
  else:
    return True



def is_connected_socket(sock):
  """
  Returns True if the socket is part of a connection.
  """

  if ENABLE_TCP_DATA_MATCHING:
    return sock in tcp_sockets
  else:
    return True



def addr_dont_care(ip, port):
  """
  If it returns True, then this is an address that we don't care about.
  We might get some false negatives though, so a return value of False
  doesn't guarantee that we care about this address.
  """

  if not ip:
    return False

  ip = ipaddr.IPAddress(ip)

  if ip.version == 6 and ip.ipv4_mapped:
    ip = ip.ipv4_mapped

  if (ip, port) in IGNORE_ADDRS or (ip, 0) in IGNORE_ADDRS:
    return True

  if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
    return False

  for host in HOST_INFO:
    for host_ip in host['ips']:
      if ip == host_ip:
        return False
    
    for nat_ip, nat_port in host['nats']:
      if ip == nat_ip and (port == nat_port or port == 0 or nat_port == 0):
        return False

  return True



def is_addr_match(sock_trace, private_addr, peer_trace, public_addr, is_server):
  """
  Takes the trace id of a socket, the address that socket is bound to
  (an address is an (ip, port) tuple), the trace id of another socket,
  the public address that the other socket is interacting with, and a
  boolean that is True if the local socket is receiving/accepting from
  the remote peer socket and is False if the local socket is
  sending/connecting to the peer socket. The functions determines if
  this combination is potentially part of a connection between and local
  socket and remote peer. If not, it returns (False, None), and if it
  could be a connection then (True, warnings) is returned, where warnings
  is a list of strings describing issues with this connection that
  should be brought to the user's attention. To test if a pair of sockets
  are connected, this fuction must be called twice, once for each socket.
  """

  warnings = []

  host_ips = HOST_INFO[TRACE_INFO[sock_trace]['host']]['ips']
  host_nats = HOST_INFO[TRACE_INFO[sock_trace]['host']]['nats']

  if public_addr[0]:
    public_ip = ipaddr.IPAddress(public_addr[0])

    if public_ip.is_unspecified:
      warnings.append("Peer is an unspecified address '" + public_addr[0] + "', which is not portable")

  else:
    if is_server:
      warnings.append("The server's public IP is unknown, which shouldn't happen")
    else:
      warnings.append("The clients's public IP is unknown, which may happen for UDP traffic")

  if private_addr[0]:
    private_ip = ipaddr.IPAddress(private_addr[0])

    if private_ip.is_multicast:
      warnings.append("Socket is bound to a multicast address '" + private_addr[0] + "', which is not portable")

    elif not (private_ip.is_unspecified or private_ip.is_loopback or private_ip in host_ips):
      warnings.append("Trace '" + TRACE_INFO[sock_trace]['name'] + "' is bound to '" +
          sock_trace[0] +"', which does not match any of its known private IPs")

  elif is_server:
    warnings.append("The private address of the server is unknown")

  if not public_addr[0]:
    return (True, warnings)

  public_port = public_addr[1]
  private_port = private_addr[1]

  if not public_port or not private_port:
    if is_server:
      warnings.append("Unable to verify port numbers, which should only " +
                      "happen for the client")
    public_port = 0
    private_port = 0

  if private_addr[0]:

    if private_ip.version != public_ip.version:
      warnings.append("Addresses '" + public_addr[0] + "' and '" +
          private_addr[0] + "' are not the same IP version")

    if private_ip.version == 6 and private_ip.ipv4_mapped:
      private_ip = private_ip.ipv4_mapped
      warnings.append("Address '" + private_addr[0] + "' is an IPv4 address mapped to IPv6")

    if private_ip.is_multicast and not is_server:
      private_ip = ipaddr.IPAddress("0.0.0.0")

  else:
    private_ip = ipaddr.IPAddress("0.0.0.0")

  if public_ip.version == 6 and public_ip.ipv4_mapped:
    public_ip = public_ip.ipv4_mapped
    warnings.append("Address '" + public_addr[0] + "' is an IPv4 address mapped to IPv6")

  if TRACE_INFO[peer_trace]['host'] != TRACE_INFO[sock_trace]['host']:
    if public_ip.is_loopback or public_ip.is_unspecified:
      return (False, None)

  elif public_ip.is_unspecified and public_port == private_port:
    return (True, warnings)

  if private_ip.is_unspecified:
    if public_port == private_port and (public_ip in host_ips or
        public_ip.is_loopback or public_ip.is_unspecified or public_ip.is_multicast):
      return (True, warnings)

  if private_addr == public_addr:
    return (True, warnings)

  if is_server:
    warnings.append("The server is behind a NAT")
  else:
    warnings.append("The client is behind a NAT")

  if (public_ip, public_port) in host_nats:
    for nat_private_ip, nat_private_port in host_nats[(public_ip, public_port)]:

      if private_ip.is_unspecified or private_ip == nat_private_ip:
        if private_port == nat_private_port:
          return (True, warnings)
        if nat_private_port == 0:
          if is_server:
            warnings.append("Unable to verify server port mapping")
          return (True, warnings)

  if is_server:
    warnings.append("Unable to verify server port mapping")

  if (public_ip, 0) in host_nats:
    for nat_private_ip, nat_private_port in host_nats[(public_ip, 0)]:

      if private_ip.is_unspecified or private_ip == nat_private_ip:
        if private_port == nat_private_port or nat_private_port == 0:
          return (True, warnings)

  return (False, None)



def format_addr(ip, port):
  """
  Takes an IP and port and returns a reasonable string representation.
  """

  addr_str = ip

  if not ip:
    addr_str = "[unknown]"
  else:
    ip_obj = ipaddr.IPAddress(ip)
    if ip_obj.version == 6 and port:
      addr_str = "[" + ip + "]"

  if port:
    addr_str += ":" + str(port)

  return addr_str


