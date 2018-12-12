"""
<Program Name>
  model_network_syscalls.py

<Author>
  Eleni Gessiou

<Start Date> 
  20 June 2012

<Purpose> 
  Modeling network behavior of the POSIX API system calls.
  It contains one function for every POSIX system call,
  which simulates the behavior of the particular call.
  It is also stateful: it keeps necessary state for every syscall
  has been called so far.
  I've implemented it based on Linux behavior.

<Notes>
  I don't handle readv for now
  Broad/Multicasting are not handled correctly. There are only some effort done. 

"""
import sys
import socket

# source: http://code.google.com/p/ipaddr-py/
from ipaddr import IPAddress
import ip_matching

from trace_ordering import SyscallException
from trace_ordering import SyscallError
from trace_ordering import SyscallWarning
from trace_ordering import SyscallNotice
from trace_ordering import SyscallDontCare


##### GLOBALS
AF_INET = PF_INET = 2
PF_INET6 = AF_INET6 = 30

SOCK_STREAM = 1
SOCK_DGRAM = 2

IPPROTO_TCP = 6
IPPROTO_UDP = 17
SOL_IP = IPPROTO_IP = 0

SOL_UDP = 17 
SOL_TCP = 6
SOL_SOCKET = 0xffff
SOL_IP = 1

IP_MULTICAST_IF = 32
IP_MULTICAST_TTL = 33
IP_MULTICAST_LOOP = 34
IP_ADD_MEMBERSHIP = 35
IP_DROP_MEMBERSHIP = 36

# More setsockopt / getsockopt

SO_DEBUG = 0x0001        # turn on debugging info recording 
SO_ACCEPTCONN = 0x0002   # socket has had listen()
SO_REUSEADDR = 0x0004    # allow local address reuse
SO_KEEPALIVE = 0x0008    # keep connections alive
SO_DONTROUTE = 0x0010    # just use interface addresses
SO_BROADCAST = 0x0020    # permit sending of broadcast msgs
SO_USELOOPBACK = 0x0040  # bypass hardware when possible
SO_LINGER = 0x0080       # linger on close if data present (in ticks)
SO_OOBINLINE = 0x0100    # leave received OOB data in line
SO_REUSEPORT = 0x0200    # allow local address & port reuse
SO_TIMESTAMP = 0x0400    # timestamp received dgram traffic
SO_ACCEPTFILTER = 0x1000 # there is an accept filter
SO_DONTTRUNC = 0x2000    # APPLE: Retain unread data
SO_WANTMORE = 0x4000     # APPLE: Give hint when more data ready
SO_WANTOOBFLAG = 0x8000  # APPLE: Want OOB in MSG_FLAG on receive
SO_SNDBUF = 0x1001               # send buffer size
SO_RCVBUF = 0x1002               # receive buffer size
SO_SNDLOWAT = 0x1003             # send low-water mark
SO_RCVLOWAT = 0x1004             # receive low-water mark
SO_SNDTIMEO = 0x1005             # send timeout
SO_RCVTIMEO = 0x1006             # receive timeout
SO_ERROR = 0x1007                # get error status and clear
SO_TYPE = 0x1008                 # get socket type
SO_NREAD = 0x1020                # APPLE: get 1st-packet byte count
SO_NKE = 0x1021                  # APPLE: Install socket-level NKE
SO_NOSIGPIPE = 0x1022            # APPLE: No SIGPIPE on EPIPE
SO_NOADDRERR = 0x1023            # APPLE: Returns EADDRNOTAVAIL when src is not available anymore
SO_NWRITE = 0x1024               # APPLE: Get number of bytes currently in send socket buffer
SO_REUSESHAREUID = 0x1025        # APPLE: Allow reuse of port/socket by different userids
SO_NOTIFYCONFLICT = 0x1026       # APPLE: send notification if there is a bind on a port which is already in use
SO_UPCALLCLOSEWAIT = 0x1027      # APPLE: block on close until an upcall returns
SO_LINGER_SEC = 0x1080           # linger on close if data present (in seconds)
SO_RESTRICTIONS = 0x1081         # APPLE: deny inbound/outbound/both/flag set
SO_RESTRICT_DENYIN = 0x00000001  # flag for SO_RESTRICTIONS - deny inbound
SO_RESTRICT_DENYOUT = 0x00000002 # flag for SO_RESTRICTIONS - deny outbound
SO_RESTRICT_DENYSET = 0x80000000 # flag for SO_RESTRICTIONS - deny has been set
SO_RANDOMPORT = 0x1082           # APPLE: request local port randomization
SO_NP_EXTENSIONS = 0x1083        # To turn off some POSIX behavior
SO_LABEL = 0x1010                # socket's MAC label
SO_PEERLABEL = 0x1011            # socket's peer MAC label
SO_PRIORITY = 12

TCP_NODELAY = 0x01           # don't delay send to coalesce packets
TCP_MAXSEG = 0x02            # set maximum segment size
TCP_NOPUSH = 0x04            # don't push last block of write
TCP_NOOPT = 0x08             # don't use TCP options
TCP_KEEPALIVE = 0x10         # idle time used when SO_KEEPALIVE is enabled
TCP_CONNECTIONTIMEOUT = 0x20 # connection timeout
PERSIST_TIMEOUT = 0x40       # time after which a connection in persist timeout
                             # will terminate. 
                             # see draft-ananth-tcpm-persist-02.txt
TCP_RXT_CONNDROPTIME = 0x80  # time after which tcp retransmissions will be
                             # stopped and the connection will be dropped
TCP_RXT_FINDROP = 0x100      # When set, a connection is dropped after 3 FINs


O_NONBLOCK = 04000 

# recv flags
MSG_OOB = 0x1	     # process out-of-band data

# The MSG_PEEK flag causes the receive operation to return data
# from the beginning of the receive queue without removing that data from the queue.  
# Thus, a subsequent receive call will return the same data.
MSG_PEEK = 0x2	     # peek at incoming message
MSG_WAITALL = 0x40   # wait for full request or error

CLONE_FILES = 0x00000400

# FCNTL
F_DUPFD =  0
F_SETFD =  2
F_SETFL = 4

# SHUTDOWN
SHUT_RD = 0
SHUT_WR = 1
SHUT_RDWR = 2

# broadcast ip addrs
broadcast_ip = ['255.255.255.255']


# TODO: even if MSG_OOB flag is set, if SO_OOBINLINE option is also set for the socket
# data are delivered in-line.
# Out-of-band data (called "urgent data" in TCP)


##### Global Structures keeping the necessary state for the model

# keep general info about sockets: 
# sockets[(node_name, sockfd)] = {'domain': dom, 'type': typ, 'protocol': prot, 
# 'local_ip': None, 'local_port': None, 'peer_ip': None, 'peer_port': None, 
# 'state': state, 'nonblock': nonblock, 'sndbuf': (131070, 0), 'rcvbuf': (262140, 0)}

# Valid values are the following:
# domain/address family = AF_INET = PF_INET = 2 or PF_INET6 = AF_INET6 = 10
# type = SOCK_STREAM = 1 or SOCK_DGRAM = 2 or SOCK_RAW	= 3
# if protocol != 0 then it shall specify a protocol that is supported by the address family
# if protocol == 0, the default protocol for this address family and type shall be used.
# for the 'state' field there are the following options : 'CREATED', 'BINDED', 'CONNECTED', 'LISTEN' 
# the sndbuf and rcvbuf size is initiated with the default value Linix uses
sockets = dict()


# socket fds that are in use
active_sockets = set([])


# The following list of tuples differs on how it handles messages:
# - for TCP, we add the message sent in the buffer and in a receive call
# we pop the corresponding part of the buffer
# - for UDP, we add all the messages in a list during the send calls
# and we just mark them as read in receive calls. This way we eliminate
# false positives for multicasting applications where there are many receivers
tcp_tuples = []
udp_tuples = []


# keep a list of non-AF_INET sockets, because we don't care about them
non_internet_sockets = []


# connected sockets waiting to get accepted
pending_connections = dict()


# keeps information about possible network misbehavior, if poll/select returns timeout
poll_timeout = set([])



# http://linux.die.net/man/2/socket
def socket_syscall(node_name, args, ret):

   # unpack the arguments and the return value
   dom, typ, prot = args
   sockfd, impl_errno = ret

   # On error, -1 is returned, and errno is set appropriately
   # in this case model doesn't update it's internal memory and let the caller
   # know that from now on we won't care about this fd
   if sockfd < 0:
      raise SyscallDontCare("socket_syscall", 'MINUS_FD', "Socket returned a negative file descriptor.")	 


   # AF_INET = PF_INET = 2, I care only for internet domain sockets
   # PF_INET6 = AF_INET6 = 10
   # handle both IPv4 and IPv6 implementations
   if dom == PF_INET or dom == PF_INET6:

      # SOCK_STREAM
      if typ == SOCK_STREAM:

         # if protocol == 0, the default protocol for this address family and type shall be used.
	 if prot == 0:
	    prot = IPPROTO_TCP
      
	 if prot != IPPROTO_TCP:
	    raise SyscallWarning("socket_syscall", 'EPROTOTYPE', 
                  "[Application Error] The socket type is not supported by the protocol.")
         
	 nonblock = (0, 0)

      # 2050 = it's SOCK_DGRAM with flag SOCK_NONBLOCK = O_NONBLOCK
      elif typ == 2050 or typ == SOCK_DGRAM:
	 if typ == 2050:			    
	    nonblock = (1, 0)
	 else:
	    nonblock = (0, 0)

	 typ = SOCK_DGRAM

         # if protocol == 0, the default protocol for this address family and type shall be used.
	 if prot == 0:
	    prot = IPPROTO_UDP

	 if prot != IPPROTO_UDP and prot != IPPROTO_IP:
	    raise SyscallWarning("socket_syscall", 'EPROTOTYPE', 
                  "[Application Error] The socket type is not supported by the protocol.")
  
      # the socket syscall creates new active sockets (and accept - see below)
      active_sockets.add((node_name, sockfd))

      # add an entry about this socket in the appropriate structure for future references
      sockets[(node_name, sockfd)] = {'domain': dom, 'type': typ, 'protocol': prot, 
         'local_ip': None, 'local_port': None, 'peer_ip': None, 'peer_port': None, 
         'state': 'CREATED', 'nonblock': nonblock, 'sndbuf': (131070, 0), 'rcvbuf': (262140, 0)}

      return (sockfd, None) 


   # TODO: make use of this list!!
   # if socket is not AF_INET just add them in a list for elimination of future false positives
   else:
      non_internet_sockets.append((node_name, sockfd))
      raise SyscallDontCare ("socket_syscall", 'DONT_CARE', "Socket is not of the AF_INET family. I'll pass..")

      


# http://linux.die.net/man/2/bind
def bind_syscall(node_name, args, ret):

   # unpack the arguments and the return value
   sock, addr, port = args
   impl_ret, err = ret

   # we only care about active sockets created
   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare("bind_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   # there are situations where the ip addr is different from the one stated in the CONFIG_FILE
   # and we don't care about them
   if addr not in broadcast_ip and ip_matching.addr_dont_care(addr, port):
      active_sockets.discard((node_name, sock))
      raise SyscallDontCare ("bind_syscall", 'DONT_CARE', "The local address is not one we care about.")

   try:
      ip = IPAddress(addr)
   except Exception:
      raise SyscallWarning("bind_syscall", 'NOT_AN_IP', addr + " is not an IP address.")


   if err == 'EADDRINUSE':
     raise SyscallNotice("bind_syscall", 'EADDRINUSE', "The address is already in use.")


   already_bound = sockets[(node_name, sock)]['local_ip'] != None or sockets[(node_name, sock)]['peer_ip'] != None

   if err is None:
      if addr not in broadcast_ip and ip_matching.addr_dont_care(addr, 0):
         print "[Warning] Trace", node_name, "is binding to", repr(addr),
         print "but that IP is not listed in its host's configuration." 

      # Update state if implementation succeeded even if it was unexpected
      # since there sin't really anything else we can do about it.
      sockets[(node_name, sock)]['local_ip'] = addr
      sockets[(node_name, sock)]['local_port'] = port
      sockets[(node_name, sock)]['state'] = 'BINDED'

   if already_bound:
      raise SyscallWarning("bind_syscall", 'EINVAL', "[Application Error] The socket is already bound to an address")

   # check if the socket shares some same features with other active sockets
   # since the real execution hasn't return an error, we can throw a warning.
   for socket in active_sockets:

      if socket != (node_name, sock) and port != 0 and sockets[socket]['local_port'] == port:
         if sockets[socket]['local_ip'] == addr:
            message = "Another socket is already bound to that address and port"
         elif addr == '0.0.0.0' or addr == '::':
            message = "Binding to unspecified address when port is already in use"
         elif sockets[socket]['local_ip'] == '0.0.0.0' or sockets[socket]['local_ip'] == '::':
            message = "Another socket is already bound to an unspecified address and that port"
         else:
            continue

         # TODO: Check inheritance and implementation result
         # if another socket is using the same local_port but the reuseport option in both sockets
         # is set, it's ok!
         if sockets[socket].get('reuseport', (0, 0))[0] == 1 and \
               sockets[(node_name, sock)].get('reuseport', (0, 0))[0] == 1:
            continue

         if sockets[socket].get('reuseaddr', (0, 0))[0] == 1:
            raise SyscallWarning("bind_syscall", 'EADDRINUSE', "[Portability Issue] " + message +
            ", and the conflicting socket is using SO_REUSEADDR to allow rebinding, which is not portable")

         raise SyscallWarning("bind_syscall", 'EADDRINUSE', "[Application Error] " + message + ".")


   if err != None:
      raise SyscallWarning("bind_syscall", 'UNEXPECTED_FAILURE', "Bind failed unexpectedly.")

   return (0, None)



# http://linux.die.net/man/2/listen
def listen_syscall(node_name, args, ret):

   # unpack the arguments and the return value
   sock, log = args
   impl_ret, err = ret

   # we only care about active sockets created
   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare("listen_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   # check for every possible sistuation of error
   if sockets[(node_name, sock)]['local_ip'] == None and sockets[(node_name, sock)]['state'] != 'BINDED':
      raise SyscallWarning("listen_syscall", 'EDESTADDRREQ', \
            "[Application Error] The socket is not bound to a local address, \
            and the protocol does not support listening on an unbound socket.")

   if sockets[(node_name, sock)]['state'] == 'CONNECTED':
      raise SyscallWarning("listen_syscall", 'EINVAL', 
            "[Application Error] The socket is already connected.")

   if sockets[(node_name, sock)]['protocol'] == IPPROTO_UDP or sockets[(node_name, sock)]['protocol'] == IPPROTO_IP:
      raise SyscallWarning("listen_syscall", 'EOPNOTSUPP', 
            "[Application Error] The socket protocol does not support listen().")

   if err is not None:
      raise SyscallWarning("listen_syscall", 'UNEXPECTED_FAILURE', "Listen failed unexpectedly.")

   # if everything is successful update the state of the socket and return success!
   sockets[(node_name, sock)]['state'] = 'LISTEN'

   return (0, None)



# http://linux.die.net/man/2/accept
def accept_syscall(node_name, args, ret):

   # unpack the arguments and the return value
   sock, peer_addr, peer_port = args
   connected_socket, err = ret

   if not isinstance(connected_socket, int):
      raise SyscallDontCare("accept_syscall", 'DONT_CARE', "The connected socket is not an integer..")
      
   if connected_socket == -1:

      # handlind non or blocking sockets...
      if err == 'EAGAIN' or err == 'EWOULDBLOCK':
         if sockets[(node_name, sock)]['nonblock'] == (1, 1):
            raise SyscallNotice("accept_syscall", 'EAGAIN/EWOULDBLOCK', "Resource temporarily unavailable.")

         elif sockets[(node_name, sock)]['nonblock'] == (1, 0):
            raise SyscallWarning("accept_syscall", 'COULD_HAVE_BLOCKED',
                  "[Portability Issue] The socket inherited the nonblocking flag from the server socket that returned it, \
                  which does not consistently happen across operating systems.")
         else:
            raise SyscallWarning("accept_syscall", 'EXPECTED_BLOCKING',
                  "[Network Misbehavior] Socket does not have the nonblocking flag set.")
      else:
         raise SyscallWarning("accept_syscall", 'UNEXPECTED_FAILURE', "Accept failed unexpectedly.")
         

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare("accept_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   if peer_addr not in broadcast_ip and ip_matching.addr_dont_care(peer_addr, peer_port):
      raise SyscallDontCare("accept_syscall", 'DONT_CARE', "The remote address is not one we care about.")

   if (node_name, sock) not in pending_connections or not pending_connections[(node_name, sock)]:
      raise SyscallError("accept_syscall", 'NO_PENDING_CONN', "There are no pending connections.")


   for require_data_matches in [True, False]:
      for require_established in [True, False]:
         if (require_data_matches or require_established) and not ip_matching.ENABLE_TCP_DATA_MATCHING:
            continue

         # Search through the available connections until we find one that matches the one we want to accept
         for index in xrange(len(pending_connections[(node_name, sock)])):
            peer_name, peer_fd = pending_connections[(node_name, sock)][index]

            if require_established and sockets[(peer_name, peer_fd)]['state'] != 'CONNECTED':
               continue

            if require_data_matches and not ip_matching.is_socket_match(
                  (peer_name, peer_fd), (node_name, connected_socket)):
               continue

            private_addr = (sockets[(peer_name, peer_fd)]['local_ip'], sockets[(peer_name, peer_fd)]['local_port'])

            is_match, warnings = ip_matching.is_addr_match(peer_name, private_addr, node_name, (peer_addr, peer_port), False)

            if is_match:

               print "TCP server socket %s%d" % (node_name, sock),
               if sockets[(node_name, sock)]['local_ip']:
                  print "(private address " + ip_matching.format_addr(sockets[(node_name, sock)]['local_ip'], 
                        sockets[(node_name, sock)]['local_port']) + ")",

               print "returning socket %s%d," % (node_name, connected_socket),
               print "which is connected to socket %s%d" % (peer_name, peer_fd),

               if peer_addr:
                  print "(public address " + ip_matching.format_addr(peer_addr, peer_port) + ")",
               print

               for warning in warnings:
                  print " * [Warning]", warning

               if not require_data_matches and ip_matching.ENABLE_TCP_DATA_MATCHING:
                  print " * [Warning] The data sent/received by this pair of sockets doesn't match"

               pending_connections[(node_name, sock)].pop(index)

               # create a new socket with the same socket type protocol and address family as the specified socket, 
               # and allocate a new file descriptor for that socket.
               active_sockets.add((node_name, connected_socket))

               # the child fd inherits the parent 
               s_info = sockets[(node_name, sock)]
               sockets[(node_name, connected_socket)] = s_info.copy()


               # indicate that flag is inhereted from parent and not set explicitly
               for k in sockets[(node_name, connected_socket)].iterkeys():
                  if k != 'domain' and k != 'type' and k != 'protocol' and k != 'local_ip' and k != 'local_port' and \
                     k != 'state' and k != 'flags' and k != 'peer_ip' and k != 'peer_port':

                     sockets[(node_name, connected_socket)][k] = (sockets[(node_name, connected_socket)][k][0], 0)

               sockets[(node_name, connected_socket)]['peer_ip'] = peer_addr
               sockets[(node_name, connected_socket)]['peer_port'] = peer_port
               sockets[(node_name, connected_socket)]['state'] = 'CONNECTED'

               for t in tcp_tuples:
                  if t['connected_fd'] == (peer_name, peer_fd):
                     t['accepting_fd'] = (node_name, connected_socket)
               
               return (connected_socket, None)


   raise SyscallError("accept_syscall", 'NO_PENDING_CONN', "There are no pending connections from that peer address.")




# TODO: handle getsockopt(49, SOL_SOCKET, SO_ERROR, [111], [4]) = 0  
# http://linux.die.net/man/2/connect          
def connect_syscall(node_name, args, ret):

   # unpack the arguments and the return value
   sock, addr, port = args
   impl_ret, err = ret

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare ("connect_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   try:
      ip = IPAddress(addr)
   except Exception:
      raise SyscallWarning("connect_syscall", 'NOT_AN_IP', addr + " is not an IP address.")


   # Check if socket is connection-mode(IPPROTO_TCP) or not (IPPROTO_UDP)

   # if IPPROTO_UDP then set the socket's peer address, and no connection is made
   if sockets[(node_name, sock)]['protocol'] == IPPROTO_UDP:

      if err is None:
         sockets[(node_name, sock)]['peer_ip'] = addr
         sockets[(node_name, sock)]['peer_port'] = port

      if addr not in broadcast_ip and ip_matching.addr_dont_care(addr, port):
         raise SyscallDontCare ("connect_syscall", 'DONT_CARE', "The remote address is not one we care about.")

      # If the socket protocol supports broadcast (eg UDP) and the specified address is a broadcast address 
      # for the socket protocol, sendto() shall fail if the SO_BROADCAST option is not set for the socket.
      if addr in broadcast_ip and ('broadcast' not in sockets[(node_name, sock)] or sockets[(node_name, sock)]['broadcast'][0] != 1):
         
         if 'broadcast' in sockets[(node_name, sock)] and sockets[(node_name, sock)]['broadcast'][0] != 1 and sockets[(node_name, sock)]['broadcast'][1] == 0:
            print "[Warning] Socket has inherited SO_BROADCAST flag from parent and cannot send data. I will raise an error.."

         raise SyscallWarning("connect_syscall", "EACCES", "[Application Error] Sockets's trying to connect to broadcast address without using the broadcast flag.")

      if not IPAddress(addr).is_loopback and sockets[(node_name, sock)]['local_ip'] is not None and \
            IPAddress(sockets[(node_name, sock)]['local_ip']).is_loopback:
         raise SyscallWarning("connect_syscall", 'EINVAL', "UDP connect on socket bound to loopback to non-loopback IP.")

      if err is not None:
         raise SyscallWarning("connect_syscall", 'UNEXPECTED_FAILURE', "UDP connect failed unexpectedly.")

      return (0, None)

   # if IPPROTO_TCP then attempt to establish a connection to the peer address
   elif sockets[(node_name, sock)]['protocol'] == IPPROTO_TCP:

      # stream sockets may successfully connect() only once
      if sockets[(node_name, sock)]['state'] == 'CONNECTED':
         raise SyscallWarning("connect_syscall", 'EISCONN', "[Application Error] Socket is already connected.")

      if addr not in broadcast_ip and ip_matching.addr_dont_care(addr, port):
         active_sockets.discard((node_name, sock))
         raise SyscallDontCare ("connect_syscall", 'DONT_CARE', "The remote address is not one we care about.")

      # Don't process nonblocking connects, but make a note of the connection in progress
      if err == 'EINPROGRESS' or err == 'EALREADY' or err == "EWOULDBLOCK":

         if 'PENDING' in sockets[(node_name, sock)]['state']:
            raise SyscallNotice("connect_syscall", 'EALREADY', "The socket is nonblocking and a previous \
                  connection attempt has not yet been completed. ")
         else:

            sockets[(node_name, sock)]['peer_ip'] = addr
            sockets[(node_name, sock)]['peer_port'] = port
            sockets[(node_name, sock)]['state'] = 'PENDING'

            # This allows us to consider the socket if we are matching up data send/received.
            if ip_matching.ENABLE_TCP_DATA_MATCHING and ip_matching.is_connected_socket((node_name, sock)):
               try:
                  connect_syscall(node_name, args, (0, None))
                  sockets[(node_name, sock)]['state'] = 'PENDING/CONNECTED'
               except SyscallException:
                  pass

            # check if there is already a socket that shares common features and return the corresponding exception
            for node, fd in active_sockets:
               if node == node_name and fd != sock and sockets[(node, fd)]['state'] == 'PENDING':
                  raise SyscallNotice("connect_syscall", "OVERLAPPING_CONNECTS", \
                        "This trace already has one or more nonblocking connects pending, \
                        which may mean that the corresponding accepts are improperly matched.")

            if not IPAddress(addr).is_loopback and sockets[(node_name, sock)]['local_ip'] is not None and \
                  IPAddress(sockets[(node_name, sock)]['local_ip']).is_loopback:
               raise SyscallWarning("connect_syscall", 'EINVAL', "TCP connect on socket bound to loopback to non-loopback IP.")

            if sockets[(node_name, sock)]['nonblock'] == (1, 1):
               raise SyscallNotice("connect_syscall", 'EINPROGRESS', 
                     "The socket is nonblocking and the connection cannot be completed immediately.")

            elif sockets[(node_name, sock)]['nonblock'] == (1, 0):
               raise SyscallWarning("connect_syscall", 'COULD_HAVE_BLOCKED',
                     "[Portability Issue] The socket inherited the nonblocking flag from the server socket that returned it, \
                     which does not consistently happen across operating systems.")
            else:
               raise SyscallWarning("connect_syscall", 'EXPECTED_BLOCKING',
                     "[Network Misbehavior] Socket does not have the nonblocking flag set.")


      if sockets[(node_name, sock)]['state'] == 'PENDING/CONNECTED' and err is None:
         sockets[(node_name, sock)]['state'] = 'CONNECTED'

         if not IPAddress(addr).is_loopback and sockets[(node_name, sock)]['local_ip'] is not None and \
               IPAddress(sockets[(node_name, sock)]['local_ip']).is_loopback:
            raise SyscallWarning("connect_syscall", 'EINVAL', "TCP connect on socket bound to loopback to non-loopback IP.")

         return (0, None)

      if err is None:
         # for every socket that matches to the criteria and is listening we add this pending connection.
         # We have no way of knowing which is the correct peer if more than one have the same 
         # local_ip/local_port and they are listening
         for peer_socket in active_sockets:

            if sockets[peer_socket]['state'] != 'LISTEN':
               continue

            peer_addr = (sockets[peer_socket]['local_ip'], sockets[peer_socket]['local_port'])

            is_match, warnings = ip_matching.is_addr_match(peer_socket[0], peer_addr, node_name, (addr, port), True)

            if is_match:

               sockets[(node_name, sock)]['peer_ip'] = addr
               sockets[(node_name, sock)]['peer_port'] = port

               # notify the user with important info for the connection   
               print "TCP socket %s%d" % (node_name, sock),
               if sockets[(node_name, sock)]['local_ip']:
                  print "(private address " + ip_matching.format_addr(sockets[(node_name, sock)]['local_ip'], 
                        sockets[(node_name, sock)]['local_port']) + ")",
               print "connecting to socket %s%d" % peer_socket,
               if addr:
                  print "(public address " + ip_matching.format_addr(addr, port) + ")",
               print

               for warning in warnings:
                  print " * [Warning]", warning

               sockets[(node_name, sock)]['state'] = 'CONNECTED'

               # create an entry for the connection with all the necessary info
               connection_dict = {'accepting_fd': None, 'a_buffer': ("", 0, 0), 'a_shutdown': False,
                                  'connected_fd': (node_name, sock), 'c_buffer': ("", 0, 0), 'c_shutdown': False}

               tcp_tuples.append(connection_dict)

               if peer_socket not in pending_connections:
                  pending_connections[peer_socket] = []

               pending_connections[peer_socket].append((node_name, sock))

               if not IPAddress(addr).is_loopback and sockets[(node_name, sock)]['local_ip'] is not None and \
                     IPAddress(sockets[(node_name, sock)]['local_ip']).is_loopback:
                  raise SyscallWarning("connect_syscall", 'EINVAL', "TCP connect on socket bound to loopback to non-loopback IP.")

               return (0, None)

      if err == None:
         raise SyscallError("connect_syscall", 'ECONNREFUSED', "[Ambiguous Misbehavior] \
               The target address was not listening for connections or refused the connection request.")

      elif not IPAddress(addr).is_loopback and sockets[(node_name, sock)]['local_ip'] is not None and \
            IPAddress(sockets[(node_name, sock)]['local_ip']).is_loopback:
         raise SyscallWarning("connect_syscall", 'EINVAL', "TCP connect on socket bound to loopback to non-loopback IP.")

      elif err == 'ECONNREFUSED' or err == 'EINVAL':
         raise SyscallWarning("connect_syscall", 'ECONNREFUSED', "[Ambiguous Misbehavior] \
               The target address was not listening for connections.")
      else:
         raise SyscallWarning("connect_syscall", 'UNEXPECTED_FAILURE', "TCP connect failed with an unexpected error.")



# write_syscall is the same with flags = 0
# and writev_syscall
# may be used only when the socket is in a connected state
# it should only be used for IPPROTO_TCP protocol
# http://linux.die.net/man/2/send
def send_syscall(node_name, args, ret):

   sock, msg, flags = args
   msg_len, err = ret

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare ("send_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   # if it's a UDP socket, call sendto instead
   if sockets[(node_name, sock)]['protocol'] != IPPROTO_TCP:
      return sendto_syscall(node_name, (sock, msg, flags, '', 0), ret)

   if 'PENDING' in sockets[(node_name, sock)]['state']:
      if err == 'EAGAIN' or err == 'EWOULDBLOCK':
         raise SyscallNotice("recv_syscall", 'EAGAIN/EWOULDBLOCK', "No data was sent.")

      # Node didn't actually call connect again to see that the nonblocking connect succeeded
      connect_syscall(node_name, (sock, sockets[(node_name, sock)]['peer_ip'],
                       sockets[(node_name, sock)]['peer_port']), ret)


   if sockets[(node_name, sock)]['state'] != 'CONNECTED':
      raise SyscallWarning("send_syscall", 'ENOTCONN', "[Application Error] The descriptor is not connected.")

   # MSG_OOB with datagram socket is not allowed
   if flags == MSG_OOB and (sockets[(node_name, sock)]['type'] != SOCK_STREAM or
         'oobdata' not in sockets[(node_name, sock)] or sockets[(node_name, sock)]['oobdata'] != 1):
      raise SyscallWarning("send_syscall", 'EOPNOTSUPP', "[Application Error] \
            Some bit in the flags argument is inappropriate for the socket type.")

   if flags == MSG_OOB and ('oobdata' not in sockets[(node_name, sock)] or sockets[(node_name, sock)]['oobdata'] != 1):
      raise SyscallNotice("send_syscall", 'OOB_DATA', 'Sending out-of-band data..')

   if msg_len == 0:
      return (0, None)

   elif msg_len > 0:
      msg = msg.decode('string_escape')

      if len(msg) > msg_len:
         msg = msg[:msg_len]

   elif err != 'EPIPE' and err != 'ECONNRESET':
      if err == 'EAGAIN' or err == 'EWOULDBLOCK':

         # handle all the non and blocking cases
         if sockets[(node_name, sock)]['nonblock'] == (1, 1):
            raise SyscallNotice("send_syscall", 'EAGAIN/EWOULDBLOCK', "No data was sent.")

         elif sockets[(node_name, sock)]['nonblock'] == (1, 0):
            raise SyscallWarning("send_syscall", 'COULD_HAVE_BLOCKED',
                  "[Portability Issue] The socket inherited the nonblocking flag from the server socket that returned it, \
                  which does not consistently happen across operating systems.")
         else:
            raise SyscallWarning("send_syscall", 'EXPECTED_BLOCKING',
                  "[Network Misbehavior] Socket does not have the nonblocking flag set.")
      else:
         raise SyscallWarning("send_syscall", 'UNEXPECTED_FAILURE', "Send failed unexpectedly.")


   # among all the socket tuples, find the correct socket either in the connected of the accepting sockets.
   for t in tcp_tuples:
      
      # the socket can be found either in the 'accepting' or the 'connected' part of the tuple
      # the only difference is who initiated the connection; whatever socket called connect will be in the
      # 'connected' part while the socket that accepted the connection will be in the 'accepting' part

      if (node_name, sock) == t['accepting_fd']:

         if msg_len < 0:
            if t['a_shutdown'] or t['connected_fd'] not in active_sockets:
               raise SyscallWarning("send_syscall", 'EPIPE/ECONNRESET', "The connection has been closed.")
            else:
               raise SyscallError("send_syscall", 'CONN_NOT_CLOSED', "The connection has not been closed yet.")

         # simulate sending the msg by adding the msg in the string buffer of the socket
         if len(t['a_buffer'][0]) == t['a_buffer'][1]:
            t['a_buffer'] = (t['a_buffer'][0] + msg, t['a_buffer'][1] + msg_len, t['a_buffer'][2] + msg_len)
         else:
            t['a_buffer'] = (t['a_buffer'][0], t['a_buffer'][1] + msg_len, t['a_buffer'][2] + msg_len)

         if t['a_shutdown'] or t['connected_fd'] not in active_sockets:
            raise SyscallWarning ("send_syscall", 'EPIPE/ECONNRESET', "The connection has been closed.")

         if t['a_buffer'][1] > sockets[(node_name, sock)]['sndbuf'][0]:
	    raise SyscallWarning ("send_syscall", 'MSG_>_BUFSIZE', "[Application Error] \
                  Sending this message has caused data in the buffer to exceed the buffer size.")

	 # check network error due to poll/select seeing nothing
	 if t['connected_fd'] in poll_timeout:
	    poll_timeout.remove(t['connected_fd'])

	    raise SyscallWarning ("send_syscall", 'NETWORK_ERROR_%s%d' % t['connected_fd'], 
                  "[Possible Network Misbehavior] Poll/Select returned nothing although there is 'data in the air'!!")
	    
	 return (msg_len, None)


      if (node_name, sock) == t['connected_fd']:

         if msg_len < 0:
            if t['c_shutdown'] or (t['accepting_fd'] is not None and t['accepting_fd'] not in active_sockets):
               raise SyscallWarning("send_syscall", 'EPIPE/ECONNRESET', "The connection has been closed.")
            else:
               raise SyscallError("send_syscall", 'CONN_NOT_CLOSED', "The connection has not been closed yet.")

         if len(t['c_buffer'][0]) == t['c_buffer'][1]:
            t['c_buffer'] = (t['c_buffer'][0] + msg, t['c_buffer'][1] + msg_len, t['c_buffer'][2] + msg_len)
         else:
            t['c_buffer'] = (t['c_buffer'][0], t['c_buffer'][1] + msg_len, t['c_buffer'][2] + msg_len)

         if t['c_shutdown'] or (t['accepting_fd'] is not None and t['accepting_fd'] not in active_sockets):
            raise SyscallWarning ("send_syscall", 'EPIPE/ECONNRESET', "The connection has been closed.")

         if t['c_buffer'][1] > sockets[(node_name, sock)]['sndbuf'][0]:
	    raise SyscallWarning ("send_syscall", 'MSG_>_BUFSIZE', "[Application Error] Sending this \
                  message has caused data in the buffer to exceed the buffer size.")

	 # check network error due to poll/select seeing nothing
	 if t['accepting_fd'] in poll_timeout:
	    poll_timeout.remove(t['accepting_fd'])
	    raise SyscallWarning ("send_syscall", 'NETWORK_ERROR_%s%d' % t['accepting_fd'], \
                  "[Possible Network Misbehavior] Poll/Select returned nothing although there is 'data in the air'!!")

	 return (msg_len, None)
    
   raise SyscallError("send_syscall", 'MSGNOTSENT', "[Possible Network Misbehavior] The message was not sent, \
         because no established connection found.")




# same: sendmsg_syscall with msg_len = len(msg)
# http://linux.die.net/man/2/sendto
def sendto_syscall(node_name, args, ret):

   # unpack the arguments and the return value 
   sock, msg, flags, dest_addr, dest_port = args
   msg_len, err = ret

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare ("sendto_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   # if IP addr/port is not defined, use send instead
   if sockets[(node_name, sock)]['protocol'] == IPPROTO_TCP:
      send_syscall(node_name, (sock, msg, flags), ret)

      if dest_addr:
         raise SyscallWarning("sendto_syscall", "EISCONN", "[Application Error] \
               The connection-mode socket was connected already but a recipient was specified.")
      return (msg_len, None)


   # If no IP and port are given, then try using the peer address we are connected to
   if (dest_addr == '' and dest_port == 0) or (dest_addr == None and dest_port == None):

      if sockets[(node_name, sock)]['peer_ip'] != None:
         dest_addr = sockets[(node_name, sock)]['peer_ip']
         dest_port = sockets[(node_name, sock)]['peer_port']
      else:
         raise SyscallWarning("sendto_syscall", "EDESTADDRREQ", "[Application Error] \
               The socket is not connection-mode, and no peer address is set.")

   try:
      ip = IPAddress(dest_addr)
   except Exception:
      raise SyscallWarning("sendto_syscall", 'NOT_AN_IP', dest_addr + " is not an IP address.")

   if dest_addr not in broadcast_ip and ip_matching.addr_dont_care(dest_addr, dest_port):
      raise SyscallDontCare("sendto_syscall", 'DONT_CARE', "The remote address is not one we care about.")

   warning = None

   if msg_len > sockets[(node_name, sock)]['sndbuf'][0]:
      warning = SyscallWarning("sendto_syscall", "MSG_>_BUFSIZE", "[Portability Issue] \
                The socket is trying to send a message larger than its send buffer size, which is not portable.")


   # If the socket protocol supports broadcast (eg UDP) and the specified address is a broadcast address 
   # for the socket protocol, sendto() shall fail if the SO_BROADCAST option is not set for the socket.
   if dest_addr in broadcast_ip and ('broadcast' not in sockets[(node_name, sock)] or 
				     sockets[(node_name, sock)]['broadcast'][0] != 1):
      
      if 'broadcast' in sockets[(node_name, sock)] and sockets[(node_name, sock)]['broadcast'][0] != 1 \
         and sockets[(node_name, sock)]['broadcast'][1] == 0:

         print "[Warning] Socket has inherited SO_BROADCAST flag from parent and cannot send data. I will raise an error.."

      warning = SyscallWarning("sendto_syscall", "EACCES", "[Application Error] Sockets's trying to broadcast a \
                message without using the broadcast flag.")

   if not IPAddress(dest_addr).is_loopback and sockets[(node_name, sock)]['local_ip'] is not None and \
      IPAddress(sockets[(node_name, sock)]['local_ip']).is_loopback:
      warning = SyscallWarning("sendto_syscall", 'EINVAL', "UDP send on socket bound to loopback to non-loopback IP.")

   if msg_len == -1:
      if warning:
         raise warning

      # handling non and blocking behavior
      if err == 'EAGAIN' or err == 'EWOULDBLOCK':

         if sockets[(node_name, sock)]['nonblock'] == (1, 1):
            raise SyscallNotice("sendto_syscall", 'EAGAIN/EWOULDBLOCK', "No data was sent.")

         elif sockets[(node_name, sock)]['nonblock'] == (1, 0):
            raise SyscallWarning("sendto_syscall", 'COULD_HAVE_BLOCKED',
                  "[Portability Issue] The socket inherited the nonblocking flag from the server socket that returned it, \
                  which does not consistently happen across operating systems.")
         else:
            raise SyscallWarning("sendto_syscall", 'EXPECTED_BLOCKING',
                  "[Network Misbehavior] Socket does not have the nonblocking flag set.")
      else:
         raise SyscallWarning("sendto_syscall", 'UNEXPECTED_FAILURE', "Sendto failed unexpectedly.")

   msg = msg.decode('string_escape')

   # especially for sendmsg
   if len(msg) > msg_len:
      msg = msg[:msg_len]

   # look for existing mappings we can use
   for t in udp_tuples:
         
      # the socket can be found either in the 'accepting' or the 'connected' part of the tuple
      # the only difference is who initiated the communication; whatever socket tried to send first will be in the
      # 'connected' part while the socket that received will be in the 'accepting' part
      if (node_name, sock) in t['accepting_fd_list']: 

         if (t['connected_ip'] == dest_addr and t['connected_port'] == dest_port):

            # simulate the behavior by adding the datagram sent in the list of datagrams
            # also keep a counter with each datagram which shows how many times is received
            # (this helps in case of the multicasting where the same datagram is being recwived
            # multiple times)
            if msg in t['a_dtgrams']:
               t['a_dtgrams'][msg] = (t['a_dtgrams'][msg][0] + 1, t['a_dtgrams'][msg][1])
            else:
               t['a_dtgrams'][msg] = (1, 0)

            # check network error due to poll/select seeing nothing
            for p in t['connected_fd_list']:
               if p in poll_timeout:
                  poll_timeout.remove(p)
                  raise SyscallWarning ("sendto_syscall", 'NETWORK_ERROR_%s%d' % p, "[Possible Network Misbehavior] \
                        Poll/Select returned nothing although there is 'data in the air'!!")

            if warning:
               raise warning

            return (msg_len, None)


      if (node_name, sock) in t['connected_fd_list']:

         # simulate behavior.
         if t['accepting_ip'] == dest_addr and t['accepting_port'] == dest_port:
            if msg in t['c_dtgrams']:
               t['c_dtgrams'][msg] = (t['c_dtgrams'][msg][0] + 1, t['c_dtgrams'][msg][1])
            else:
               t['c_dtgrams'][msg] = (1, 0)

            # check network error due to poll/select seeing nothing
            for p in t['accepting_fd_list']:

               if p in poll_timeout:
                  poll_timeout.remove(p)
                  raise SyscallWarning ("sendto_syscall", 'NETWORK_ERROR_%s%d' % p, 
                        "[Possible Network Misbehavior] Poll/Select returned nothing although there is 'data in the air'!!")

            if warning:
               raise warning

            return (msg_len, None)


   # notify the user with important info for the syscall   
   print "UDP socket %s%d" % (node_name, sock),

   if sockets[(node_name, sock)]['local_ip']:
      print "(private address " + ip_matching.format_addr(sockets[(node_name, sock)]['local_ip'], 
            sockets[(node_name, sock)]['local_port']) + ")",
   print "is sending to public address " + ip_matching.format_addr(dest_addr, dest_port)

   # if no data sent before this, we will have no record about this connection, so we have to create it
   udp_tuples.append({'connected_fd_list': set([(node_name, sock)]),
      'connected_ip': None, 'connected_port': None, 'c_dtgrams': {msg: (1, 0)},
      'accepting_fd_list': set([]), 'accepting_ip': dest_addr, 'accepting_port': dest_port, 'a_dtgrams': dict()})

   if warning:
      raise warning

   return (msg_len, None)



# http://linux.die.net/man/2/sendmsg
def sendmsg_syscall(node_name, args, ret):

   sock, msg, dest_addr, dest_port, flags = args
   sendto_args = sock, msg, flags, dest_addr, dest_port

   # just call sendto instead
   return sendto_syscall(node_name, sendto_args, ret)



# http://linux.die.net/man/2/write
def write_syscall(node_name, args, ret):

   sock, msg = args
   send_args = sock, msg, 0

   # just call send instead
   return send_syscall(node_name, send_args, ret)



# http://linux.die.net/man/2/writev
def writev_syscall(node_name, args, ret):

   sock, msg, count = args
   send_args = sock, msg, 0

   # just call send instead
   return send_syscall(node_name, send_args, ret)



# Implementation is not full.. I only model this for apache..
# I assume that it sends data to TCP sockets only. Otherwise I throw an error.
# http://linux.die.net/man/2/sendfile
def sendfile_syscall(node_name, args, ret):

   sock, in_sock, offset, count = args

   # in_sock should be a file descriptor opened for reading and out_sock should be a descriptor opened for writing.
   # So, we only care about the out_sock that will be the fd that sends the data to the peer

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare ("sendfile_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   if sockets[(node_name, sock)]['protocol'] != IPPROTO_TCP:
      raise SyscallWarning("sendfile_syscall", 'NOT_IMPLEMENTED', "I assume that it sends data to TCP sockets only.")

   send_args = sock, '', 0

   # eventually call send for simulating this syscall
   return send_syscall(node_name, send_args, ret)



# http://linux.die.net/man/2/recv
def recv_syscall(node_name, args, ret):
  
   # unpack the arguments 
   sock, msg, buf_len, flags = args
   msg_len, err = ret

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare("recv_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   if sockets[(node_name, sock)]['protocol'] != IPPROTO_TCP:
      return recvfrom_syscall(node_name, (sock, msg, buf_len, flags, '', 0), ret)


   if 'PENDING' in sockets[(node_name, sock)]['state']:

      if err == 'EAGAIN' or err == 'EWOULDBLOCK':
         raise SyscallNotice("recv_syscall", 'EAGAIN/EWOULDBLOCK', "No data was received.")

      # Node didn't actually call connect again to see that the nonblocking connect succeeded
      connect_syscall(node_name, (sock, sockets[(node_name, sock)]['peer_ip'],
                       sockets[(node_name, sock)]['peer_port']), ret)

   if sockets[(node_name, sock)]['state'] != 'CONNECTED':
      raise SyscallWarning("recv_syscall", 'ENOTCONN', "[Application Error] \
            A receive is attempted on a connection-mode socket that is not connected.")

   if msg_len == -1:
      # handling non- and blocking
      if err == 'EAGAIN' or err == 'EWOULDBLOCK':
         if sockets[(node_name, sock)]['nonblock'] == (1, 1):
            raise SyscallNotice("recv_syscall", 'EAGAIN/EWOULDBLOCK', "No data was received.")

         elif sockets[(node_name, sock)]['nonblock'] == (1, 0):
            raise SyscallWarning("recv_syscall", 'COULD_HAVE_BLOCKED',
                  "[Portability Issue] The socket inherited the nonblocking flag from the server socket that returned it, \
                  which does not consistently happen across operating systems.")
         else:
            raise SyscallWarning("recv_syscall", 'EXPECTED_BLOCKING',
                  "[Network Misbehavior] Socket does not have the nonblocking flag set.")
      else:
         raise SyscallWarning("recv_syscall", 'UNEXPECTED_FAILURE', "Recv failed unexpectedly.")


   if msg_len > buf_len:
      raise SyscallWarning("recv_syscall", 'MSG_BIGGER_THAN_BUFFER', "[Application Error] Message is bigger than the buffer size!!")

   msg = msg.decode('string_escape')
   msg_received = ""

   if len(msg) > msg_len:
      msg = msg[:msg_len]

   #if flags == MSG_OOB and ('oobdata' not in sockets[(node_name, sock)] or sockets[(node_name, sock)]['oobdata'] != 1):
   #   raise SyscallWarning ("recv_syscall", 'OOB_DATA', 'Receiving out-of-band data..')


   # find a socket match among all tccp tuples
   for t in tcp_tuples:

      # the socket can be found either in the 'accepting' or the 'connected' part of the tuple
      # the only difference is who initiated the connection; whatever socket called connect will be in the
      # 'connected' part while the socket that accepted the connection will be in the 'accepting' part
      if (node_name, sock) == t['accepting_fd']:

         if msg_len == 0 and not t['c_shutdown'] and (t['c_buffer'][1] != 0 or t['connected_fd'] in active_sockets):
            raise SyscallError("recv_syscall", 'NETWORK_ERROR_%s%d' % (node_name, sock), "[Possible Network Misbehavior] \
                  Data 'in the air' or connection not closed but recv/read returns 0 bytes.")

         msg_received = t['c_buffer'][0][:len(msg)]

         if msg_received != msg[:len(msg_received)]:

            # Let's start ignoring this connection and carry on since we
            # can't really recover from a data mismatch.
            active_sockets.discard(t['accepting_fd'])
            active_sockets.discard(t['connected_fd'])
            tcp_tuples.remove(t)

            raise SyscallWarning("recv_syscall", 'MSG_DONT_MATCH', "[Possible Network Misbehavior] \
                  Message trying to be received does not match the data already sent by socket %s%d. \
                  Ignoring future traffic on this connection since we can't recover." % t['connected_fd'])

         if t['c_buffer'][1] < msg_len:
            raise SyscallError("recv_syscall", 'MSGNOTSENT', "[Possible Network Misbehavior] \
                  Message trying to be received has not yet been sent.")

         # id MSG_PEEK in set don't remove the msg from the buffer, just return
         if flags == MSG_PEEK:
            return (msg_len, None)

         # simulate the networks' behavior by removing the part that is received form the stream buffer of the sender
         t['c_buffer'] = (t['c_buffer'][0][msg_len:], t['c_buffer'][1] - msg_len, t['c_buffer'][2])

         # remove any entry from poll_timeout that does receive something
         if (node_name, sock) in poll_timeout:
            poll_timeout.remove((node_name, sock))

         return (msg_len, None)



      if (node_name, sock) == t['connected_fd']:

         if t['accepting_fd'] is None:
            raise SyscallError("recv_syscall", 'MSGNOTSENT', "[Possible Network Misbehavior] \
                  The message was not sent, because the other side has not accepted the connection yet.")

         if msg_len == 0 and not t['a_shutdown'] and (t['a_buffer'][1] != 0 or
               t['accepting_fd'] in active_sockets or t['accepting_fd'] is None):
            raise SyscallError("recv_syscall", 'NETWORK_ERROR_%s%d' % (node_name, sock), "[Possible Network Misbehavior] \
                  Data 'in the air' or connection not closed but recv/read returns 0 bytes.")

         msg_received = t['a_buffer'][0][:len(msg)]

         if msg_received != msg[:len(msg_received)]:
            # Let's start ignoring this connection and carry on since we
            # can't really recover from a data mismatch.
            active_sockets.discard(t['accepting_fd'])
            active_sockets.discard(t['connected_fd'])
            tcp_tuples.remove(t)
            raise SyscallWarning("recv_syscall", 'MSG_DONT_MATCH', "[Possible Network Misbehavior] \
                  Message trying to be received does not match the data already sent by socket %s%d. \
                  Ignoring future traffic on this connection since we can't recover." % t['connected_fd'])

         if t['a_buffer'][1] < msg_len:
            raise SyscallError("recv_syscall", 'MSGNOTSENT', "[Possible Network Misbehavior] \
                  Message trying to be received has not yet been sent.")

         if flags == MSG_PEEK:
            return (msg_len, None)

         t['a_buffer'] = (t['a_buffer'][0][msg_len:], t['a_buffer'][1] - msg_len, t['a_buffer'][2])

         # remove any entry from poll_timeout that does receive something
         if (node_name, sock) in poll_timeout:
            poll_timeout.remove((node_name, sock))

         return (msg_len, None)
   
   raise SyscallError ("recv_syscall", 'MSGNOTSENT', "[Possible Network Misbehavior] \
         The message was not sent, because no established connection was found.")



# TODO: handle flags
# same for read with flags = 0
def recvfrom_syscall(node_name, args, ret):

   sock, msg, buf_len, flags, rem_ip, rem_port = args
   msg_len, err = ret

   multiaddr = ''

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare ("recvfrom_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   # if IP addr/port is not defined, use recv instead
   if sockets[(node_name, sock)]['protocol'] == IPPROTO_TCP:
      return recv_syscall(node_name, (sock, msg, buf_len, flags), ret)

   # when it comes to multicasting, keep only the ip addr of the group forgetting the initial remote addr
   if 'multicast' in sockets[(node_name, sock)]:
   
      # TODO: for now I assume it's only one group, need to support many
      # if there are more than one, check the bound port if it matches with any connected_port in tuples and keep that connected_ip
      for maddr in sockets[(node_name, sock)]['multicast']:
         multiaddr = maddr  

      if sockets[(node_name, sock)]['local_ip'] == '0.0.0.0':
         sockets[(node_name, sock)]['local_ip'] = maddr

   # TODO: MSG_TRUNC

   # source: ibm
   #if flags == MSG_OOB:
   #   if sockets[(node_name, sock)]['oobdata']:
   #	 raise SyscallWarning ("recvfrom_syscall", 'INVALID_OOB_FLAG', "It is invalid for the MSG_OOB flag to be set on when SO_OOBINLINE is set on.")


   # if UDP socket, take into consideration the peer's ip addr
   if rem_ip not in broadcast_ip and ip_matching.addr_dont_care(rem_ip, rem_port):
      raise SyscallDontCare ("recvfrom_syscall", 'DONT_CARE', "The remote address is not one we care about.")

   warning = None

   if msg_len > sockets[(node_name, sock)]['rcvbuf'][0]:
      warning = SyscallWarning("recvfrom_syscall", "MSG_>_BUFSIZE", "[Portability Issue] \
                The socket is receiving a message larger than its receive buffer size, which is not portable.")

   if msg_len == -1:
      if warning:
         raise warning

      if err == 'EAGAIN' or err == 'EWOULDBLOCK':
         if sockets[(node_name, sock)]['nonblock'] == (1, 1):
            raise SyscallNotice("recvfrom_syscall", 'EAGAIN/EWOULDBLOCK', "No data was received.")
         elif sockets[(node_name, sock)]['nonblock'] == (1, 0):
            raise SyscallWarning("recvfrom_syscall", 'COULD_HAVE_BLOCKED',
                  "[Portability Issue] The socket inherited the nonblocking flag from the server socket that returned it, \
                  which does not consistently happen across operating systems.")
         else:
            raise SyscallWarning("recvfrom_syscall", 'EXPECTED_BLOCKING',
                  "[Network Misbehavior] Socket does not have the nonblocking flag set.")
      else:
         raise SyscallWarning("recvfrom_syscall", 'UNEXPECTED_FAILURE', "Recvfrom failed unexpectedly.")
         
   if msg_len > buf_len:
      raise SyscallWarning("recvfrom_syscall", 'MSG_BIGGER_THAN_BUFFER', "[Portability Issue] \
            Message is bigger than the buffer size!!")



   if sockets[(node_name, sock)]['protocol'] == IPPROTO_UDP:

      msg = msg.decode('string_escape')

      # for recvmsg, I noticed that even if the #bytes are correct the buffer is fully filled, even if len(msg) < len(buffer)
      # so for these cases I only compare the first x bytes, where x = #bytes returned 
      if len(msg) > msg_len:
         msg = msg[:msg_len]

      if multiaddr != '':
         local_ip = multiaddr
      else:
         local_ip = sockets[(node_name, sock)]['local_ip']


      # Check for this message in mappings we already know about
      for t in udp_tuples:

         # the socket can be found either in the 'accepting' or the 'connected' part of the tuple
         # the only difference is who initiated the communication; whatever socket tried to send first will be in the
         # 'connected' part while the socket that received will be in the 'accepting' part

         if (node_name, sock) in t['accepting_fd_list']: 

            if t['connected_ip'] == rem_ip and t['connected_port'] == rem_port:

               if msg in t['c_dtgrams'] and (t['c_dtgrams'][msg][0] > t['c_dtgrams'][msg][1] or multiaddr != ''):
                  if flags != MSG_PEEK:
                     # simulate the action of receiving datagram by incrementing the counter for this dtgram by one
                     t['c_dtgrams'][msg] = (t['c_dtgrams'][msg][0], t['c_dtgrams'][msg][1] + 1)

		  # remove any entry from poll_timeout that does receive something
		  if (node_name, sock) in poll_timeout:
		     poll_timeout.remove((node_name, sock))

                  if warning:
                     raise warning

                  return (msg_len, None)

         if (node_name, sock) in t['connected_fd_list']:

            if t['accepting_ip'] == rem_ip and t['accepting_port'] == rem_port:

               if msg in t['a_dtgrams'] and (t['a_dtgrams'][msg][0] > t['a_dtgrams'][msg][1] or multiaddr != ''):

                  if flags != MSG_PEEK:
                     # simulate the action of receiving datagram by incrementing the counter for this dtgram by one
                     t['a_dtgrams'][msg] = (t['a_dtgrams'][msg][0], t['a_dtgrams'][msg][1] + 1)

		  # remove any entry from poll_timeout that does receive something
		  if (node_name, sock) in poll_timeout:
		     poll_timeout.remove((node_name, sock))

                  if warning:
                     raise warning

                  return (msg_len, None)


      # Check for matches with remote sockets that have send this message
      for t in udp_tuples:

         if msg in t['c_dtgrams'] and (t['c_dtgrams'][msg][0] > t['c_dtgrams'][msg][1] or multiaddr != ''):
            for peer_sock in t['connected_fd_list']:

               remote_public_addr = (rem_ip, rem_port)
               remote_private_addr = (sockets[peer_sock]['local_ip'], sockets[peer_sock]['local_port'])

               local_public_addr = (t['accepting_ip'], t['accepting_port'])
               local_private_addr = (local_ip, sockets[(node_name, sock)]['local_port'])

               local_match, local_warnings = ip_matching.is_addr_match(node_name, local_private_addr,
                                                                       peer_sock[0], local_public_addr, True)

               if not local_match:
                  continue

               remote_match, remote_warnings = ip_matching.is_addr_match(peer_sock[0], remote_private_addr,
                                                                         node_name, remote_public_addr, False)

               if not remote_match:
                  continue

               if flags != MSG_PEEK:
                  # simulate the action of receiving datagram by incrementing the counter for this dtgram by one                
                  t['c_dtgrams'][msg] = (t['c_dtgrams'][msg][0], t['c_dtgrams'][msg][1] + 1)


               t['connected_ip'] = rem_ip
               t['connected_port'] = rem_port
               t['accepting_fd_list'].add((node_name, sock))

	       
	       # remove any entry from poll_timeout that does receive something
	       if (node_name, sock) in poll_timeout:
		  poll_timeout.remove((node_name, sock))


               # notify the user of what happened
               print "UDP socket %s%d" % (node_name, sock),
               if sockets[(node_name, sock)]['local_ip']:
                  print "(private address " + ip_matching.format_addr(sockets[(node_name, sock)]['local_ip'], 
                        sockets[(node_name, sock)]['local_port']) + ")",
               print "is receiving from socket %s%d" % peer_sock,

               if rem_ip:
                  print "(public address " + ip_matching.format_addr(rem_ip, rem_port) + ")",
               print

               for warning in local_warnings + remote_warnings:
                  print " * [Warning]", warning

               if warning:
                  raise warning

               return (msg_len, None)


         if msg in t['a_dtgrams'] and (t['a_dtgrams'][msg][0] > t['a_dtgrams'][msg][1] or multiaddr != ''):

            for peer_sock in t['accepting_fd_list']:

               remote_public_addr = (rem_ip, rem_port)
               remote_private_addr = (sockets[peer_sock]['local_ip'], sockets[peer_sock]['local_port'])

               local_public_addr = (t['connected_ip'], t['connected_port'])
               local_private_addr = (local_ip, sockets[(node_name, sock)]['local_port'])

               local_match, local_warnings = ip_matching.is_addr_match(node_name, local_private_addr,
                                                                       peer_sock[0], local_public_addr, True)

               if not local_match:
                  continue

               remote_match, remote_warnings = ip_matching.is_addr_match(peer_sock[0], remote_private_addr,
                                                                         node_name, remote_public_addr, False)

               if not remote_match:
                  continue

               if flags != MSG_PEEK:
                  # simulate the action of receiving datagram by incrementing the counter for this dtgram by one                
                  t['a_dtgrams'][msg] = (t['a_dtgrams'][msg][0], t['a_dtgrams'][msg][1] + 1)


               t['accepting_ip'] = rem_ip
               t['accepting_port'] = rem_port
               t['connected_fd_list'].add((node_name, sock))

	       # remove any entry from poll_timeout that does receive something
	       if (node_name, sock) in poll_timeout:
		  poll_timeout.remove((node_name, sock))

               # notify the user for the outcome of receive
               print "UDP socket %s%d" % (node_name, sock),
               if sockets[(node_name, sock)]['local_ip']:
                  print "(private address " + ip_matching.format_addr(sockets[(node_name, sock)]['local_ip'], 
                         sockets[(node_name, sock)]['local_port']) + ")",
               print "is receiving from socket %s%d" % peer_sock,
               if rem_ip:
                  print "(public address " + ip_matching.format_addr(rem_ip, rem_port) + ")",
               print

               for warning in local_warnings + remote_warnings:
                  print " * [Warning]", warning

               if warning:
                  raise warning

               return (msg_len, None)


      for t in udp_tuples:

         if (node_name, sock) in t['accepting_fd_list'] and t['connected_ip'] == rem_ip and t['connected_port'] == rem_port:

            for datagram in t['c_dtgrams']:
               if (t['c_dtgrams'][datagram][0] > t['c_dtgrams'][datagram][1] or multiaddr != '') and datagram.startswith(msg):
                  raise SyscallError("recvfrom_syscall", 'MSGNOTSENT', "The message was not sent, \
                        but may have been truncated from a longer message.")

         if (node_name, sock) in t['connected_fd_list'] or t['accepting_ip'] == rem_ip and t['accepting_port'] == rem_port:

            for datagram in t['a_dtgrams']:
               if (t['a_dtgrams'][datagram][0] > t['a_dtgrams'][datagram][1] or multiaddr != '') and datagram.startswith(msg):
                  raise SyscallError("recvfrom_syscall", 'MSGNOTSENT', "The message was not sent, \
                        but may have been truncated from a longer message.")

         for peer_sock in t['connected_fd_list']:

            remote_public_addr = (rem_ip, rem_port)
            remote_private_addr = (sockets[peer_sock]['local_ip'], sockets[peer_sock]['local_port'])

            local_public_addr = (t['accepting_ip'], t['accepting_port'])
            local_private_addr = (local_ip, sockets[(node_name, sock)]['local_port'])

            local_match, local_warnings = ip_matching.is_addr_match(node_name, local_private_addr,
                                                                    peer_sock[0], local_public_addr, True)

            if not local_match:
               continue

            remote_match, remote_warnings = ip_matching.is_addr_match(peer_sock[0], remote_private_addr,
                                                                      node_name, remote_public_addr, False)

            if not remote_match:
               continue

            for datagram in t['c_dtgrams']:
               if (t['c_dtgrams'][datagram][0] > t['c_dtgrams'][datagram][1] or multiaddr != '') and datagram.startswith(msg):
                  raise SyscallError("recvfrom_syscall", 'MSGNOTSENT', 
                        "The message was not sent, but may have been truncated from a longer message.")

         for peer_sock in t['accepting_fd_list']:

            remote_public_addr = (rem_ip, rem_port)
            remote_private_addr = (sockets[peer_sock]['local_ip'], sockets[peer_sock]['local_port'])

            local_public_addr = (t['connected_ip'], t['connected_port'])
            local_private_addr = (local_ip, sockets[(node_name, sock)]['local_port'])

            local_match, local_warnings = ip_matching.is_addr_match(node_name, local_private_addr,
                                                                    peer_sock[0], local_public_addr, True)

            if not local_match:
               continue

            remote_match, remote_warnings = ip_matching.is_addr_match(peer_sock[0], remote_private_addr,
                                                                      node_name, remote_public_addr, False)

            if not remote_match:
               continue

            for datagram in t['a_dtgrams']:
               if (t['a_dtgrams'][datagram][0] > t['a_dtgrams'][datagram][1] or multiaddr != '') and datagram.startswith(msg):
                  raise SyscallError("recvfrom_syscall", 'MSGNOTSENT', "The message was not sent, \
                        but may have been truncated from a longer message.")

      # or MSG_OOB is set and no out-of-band data is available and either the socket's file descriptor is marked O_NONBLOCK or the socket does not support blocking to await out-of-band data.")

      # Normally, if no messages are available at the socket and O_NONBLOCK is not set on the socket's file descriptor, 
      # recvfrom() shall block until a message arrives. BUT, since the parser returns the system after it's been completed,
      # the model does not have to handle blocking operations.. (right?)
      
      raise SyscallError("recvfrom_syscall", 'MSGNOTSENT', "The message has not been sent yet.")



# http://linux.die.net/man/2/recvmsg
def recvmsg_syscall(node_name, args, ret):

   sock, msg, buf_len, rem_ip, rem_port, flags = args
   recvfrom_args = sock, msg, buf_len, flags, rem_ip, rem_port

   # call recvfrom instead
   return recvfrom_syscall(node_name, recvfrom_args, ret)



# http://linux.die.net/man/2/read
def read_syscall(node_name, args, ret):

   sock, msg, buf_len = args
   recv_args = sock, msg, buf_len, 0

   # call recv instead
   return recv_syscall(node_name, recv_args, ret)



# http://linux.die.net/man/2/close
def close_syscall(node_name, args, ret):

   sock, = args
   impl_ret, err = ret

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare("close_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   if err != None:
      if err == 'EAGAIN' or err == 'EWOULDBLOCK':
         # handling several cases if blocking sockets
         if sockets[(node_name, sock)]['linger'] and (sockets[(node_name, sock)]['linger'][0][0] == 0 or \
               sockets[(node_name, sock)]['linger'][0][1] == 0):
            raise SyscallNotice("close_syscall", 'EXPECTED_BLOCKING', "S.")
         elif sockets[(node_name, sock)]['nonblock'] == (1, 1):
            raise SyscallNotice("close_syscall", 'EAGAIN/EWOULDBLOCK', "Close did not complete.")
         elif sockets[(node_name, sock)]['nonblock'] == (1, 0):
            raise SyscallWarning("close_syscall", 'COULD_HAVE_BLOCKED',
                  "[Portability Issue] The socket inherited the nonblocking flag from the server socket that returned it, \
                  which does not consistently happen across operating systems.")
         else:
            raise SyscallWarning("close_syscall", 'EXPECTED_BLOCKING',
                  "[Network Misbehavior] Socket does not have the nonblocking flag set.")
      else:
         raise SyscallWarning("close_syscall", 'UNEXPECTED_FAILURE', "Close failed unexpectedly.")

   # remove it so we don't care about it any more
   active_sockets.remove((node_name, sock))

   # If this is a TCP server socket, shutdown any unaccepted sockets.
   if (node_name, sock) in pending_connections:
      for c_sock in pending_connections[(node_name, sock)]:
         for t in tcp_tuples:
            if t['connected_fd'] == c_sock:
               t['a_shutdown'] = True
               t['c_shutdown'] = True

   # If this is a connected TCP socket, close it.
   for t in tcp_tuples: 
      if (node_name, sock) == t['connected_fd']:
         t['a_shutdown'] = True
         if 'linger' in sockets[(node_name, sock)] and sockets[(node_name, sock)]['linger'][0][0]:
           t['c_shutdown'] = True
         if t['a_buffer'][1] != 0:
            raise SyscallNotice ("close_syscall", 'NONEMPTY_BUFFERS', "Socket's closed while there is data in the buffer.")

      if (node_name, sock) == t['accepting_fd']:
         t['c_shutdown'] = True
         if 'linger' in sockets[(node_name, sock)] and sockets[(node_name, sock)]['linger'][0][0]:
           t['a_shutdown'] = True
         if t['c_buffer'][1] != 0:
            raise SyscallNotice ("close_syscall", 'NONEMPTY_BUFFERS', "Socket's closed while there is data in the buffer.")

   # in case of UDP, file descriptors may not be in the tuples structure, since connections may not have been established.
   # in this case, look at the ip and port fields to check if they match with the ones of the socket
   if sockets[(node_name, sock)]['protocol'] == IPPROTO_UDP:
      for t in udp_tuples: # TODO: better detection of matching here
         if (t['connected_ip'] != None and t['connected_ip'] == sockets[(node_name, sock)]['local_ip'] and
            t['connected_port'] != None and t['connected_port'] == sockets[(node_name, sock)]['local_port']):

            for m in t['a_dtgrams']:
               if t['a_dtgrams'][m][1] < t['a_dtgrams'][m][0]:
                  raise SyscallWarning("close_syscall", 'NONEMPTY_BUFFERS', "Socket's closed while there is data in the buffer.")

   return (0, None)



# http://linux.die.net/man/2/shutdown
def shutdown_syscall(node_name, args, ret):

   sock, how = args
   impl_ret, err = ret

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare("shutdown_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   if how != SHUT_RD and how != SHUT_WR and how != SHUT_RDWR:
      raise SyscallWarning("shutdown_syscall", 'EINVAL', "[Application Error] The how argument is invalid.")

   if sockets[(node_name, sock)]['state'] == 'CREATED' or sockets[(node_name, sock)]['state'] == 'BINDED' or \
         sockets[(node_name, sock)]['protocol'] == IPPROTO_UDP:
      raise SyscallWarning("shutdown_syscall", 'ENOTCONN', "[Application Error] \
            Attempted to shutdown a socket that is not connected.")

   # keep info if it has been shutdown for use from other syscalls
   for t in tcp_tuples:
      if (node_name, sock) == t['connected_fd']:
         if how == SHUT_RD or how == SHUT_RDWR:
            t['a_shutdown'] = True
         if how == SHUT_WR or how == SHUT_RDWR:
            t['c_shutdown'] = True

      if (node_name, sock) == t['accepting_fd']:
         if how == SHUT_RD or how == SHUT_RDWR:
            t['c_shutdown'] = True
         if how == SHUT_WR or how == SHUT_RDWR:
            t['a_shutdown'] = True

   if sockets[(node_name, sock)]['state'] != 'CONNECTED':
      raise SyscallNotice("shutdown_syscall", 'ENOTCONN', "[Application Error] \
            Attempted to shutdown a socket that is not connected.")

   return (0, None)



# http://linux.die.net/man/2/setsockopt
# the seconf value in the tuple is '1' if the option has been set explicitly by setsockopt
# and '0' otherwise
def setsockopt_syscall(node_name, args, ret):

   sock, level, optname, optval = args
   impl_ret, err = ret

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare ("setsockopt_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   # most of the cases the level is SOL_SOCKET
   if level == SOL_SOCKET:
      
      if optname == SO_DONTROUTE or optname == SO_DEBUG or optname == SO_PRIORITY:
	 raise SyscallDontCare("setsockopt_syscall", 'DONT_CARE', 
               "We don't care about this value, since it doesn't change the state of the model: " + str(optname))

      if (optname == SO_ERROR or optname == SO_ACCEPTCONN or 
	 optname == SO_TYPE or optname == SO_SNDLOWAT or optname == SO_RCVLOWAT):
	 raise SyscallWarning("setsockopt_syscall", 'ENOPROTOOPT', "[Application Error] \
               The option is unknown at the level indicated.")

      if optname == SO_LINGER:
         sockets[(node_name, sock)]['linger'] = (optval, 1)
         return (0, None)

      # TODO: Enable sending of keep-alive messages on connection-oriented sockets.
      if optname == SO_KEEPALIVE:
	 if sockets[(node_name, sock)]['protocol'] == IPPROTO_TCP:
	    sockets[(node_name, sock)]['keepalive'] = (optval, 1)
	    return (0, None)
	 else:
	    return SyscallWarning("setsockopt_syscall", 'ENOPROTOOPT', "[Application Error] \
                   The option is unknown for that protocol.")

      # change the dedault value of the buffer
      if optname == SO_SNDBUF:
	 sockets[(node_name, sock)]['sndbuf'] = (optval, 1)
	 return (0, None)
	
      # change the dedault value of the buffer
      elif optname == SO_RCVBUF:
	 sockets[(node_name, sock)]['rcvbuf'] = (optval, 1)
	 return (0, None)

      elif optname == SO_BROADCAST:
	 if sockets[(node_name, sock)]['protocol'] == IPPROTO_UDP:
	    sockets[(node_name, sock)]['broadcast'] = (optval, 1)
	    return (0, None)
	 else:
	    return SyscallWarning("setsockopt_syscall", 'ENOPROTOOPT', "[Application Error] \
                   The option is unknown for that protocol.")

      elif optname == SO_REUSEPORT:
	 sockets[(node_name, sock)]['reuseport'] = (optval, 1)
	 return (0, None)
   
      elif optname == SO_REUSEADDR:
	 sockets[(node_name, sock)]['reuseaddr'] = (optval, 1)
	 return (0, None)

      elif optname == SO_OOBINLINE:
	 if sockets[(node_name, sock)]['protocol'] == IPPROTO_TCP:
	    sockets[(node_name, sock)]['oobdata'] = (optval, 1)
	    return (0, None)
	 else:
	    return SyscallWarning("setsockopt_syscall", 'ENOPROTOOPT', "[Application Error] \
                   The option is unknown for that protocol.")
	 return (0, None)

      elif optname == SO_RCVTIMEO:
	 sockets[(node_name, sock)]['recvtimeout'] = (optval, 1)
	 return (0, None)

      # For now return OK, but need to fix it
      else:
         raise SyscallNotice("setsockopt_syscall", 'NOT_HANDLE_OPTION', 
               "An option was given that the code does not handle: "+ str(optname))

   # handle a little bit of multicasting
   elif level == SOL_IP:

      if sockets[(node_name, sock)]['protocol'] != IPPROTO_UDP:
	 return SyscallWarning("setsockopt_syscall", 'ENOPROTOOPT', 
                "[Application Error] The level is unknown for that protocol.")

      if optname == IP_MULTICAST_IF or optname == IP_MULTICAST_TTL or optname == IP_MULTICAST_LOOP:
	 raise SyscallDontCare ("setsockopt_syscall", 'DONT_CARE', 
               "We don't care about this value, since it doesn't change the state of the model: " + str(optname))

      if optname == IP_ADD_MEMBERSHIP:
	 # unpack value
	 optval = optval.decode('string_escape')

	 multiaddr = socket.inet_ntoa(optval[:4])
	 interface = socket.inet_ntoa(optval[4:])

	 ip = IPAddress(multiaddr)
	 if not ip.is_multicast:
	    raise SyscallWarning("setsockopt_syscall", 'EINVAL', "[Application Error] \
                  Trying to add multicast membership for a non-multicast IP.")

	 # you can join the same group in several interfaces
	 try:
	    sockets[(node_name, sock)]['multicast'][multiaddr].add(interface)
	 except:
	    sockets[(node_name, sock)]['multicast'] = {multiaddr: set([interface])}
	       
	 return (0, None)

      elif optname == IP_DROP_MEMBERSHIP:
	 # unpack value
	 optval = optval.decode('string_escape')

	 multiaddr = socket.inet_ntoa(optval[:4])
	 interface = socket.inet_ntoa(optval[4:])

	 del sockets[(node_name, sock)]['multicast'][multiaddr]
	       
	 return (0, None)
      else:
         raise SyscallNotice("setsockopt_syscall", 'NOT_HANDLE_OPTION', 
               "An option was given that the code does not handle: " + str(optname))

   # TODO: I'm not sure if I have to handle SOL_TCP and SOL_UDP...
   # for now I don't
   else:
      raise SyscallNotice("setsockopt_syscall", 'UNKNOWN_LEVEL', "We don't handle this level.")



# http://linux.die.net/man/2/getsockopt
def getsockopt_syscall(node_name, args, ret):

   sock, level, optname = args
   impl_ret, err = ret

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare ("getsockopt_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")


   # most of the cases the level is SOL_SOCKET
   if level == SOL_SOCKET:

      if optname == SO_ERROR or optname == SO_DONTROUTE or optname == SO_DEBUG or optname == SO_PRIORITY:
	 raise SyscallDontCare ("setsockopt_syscall", 'DONT_CARE', 
               "We don't care about this value, since it doesn't change the state of the model: " + str(optname))

      if optname == SO_LINGER:
         if 'linger' not in sockets[(node_name, sock)]:
            sockets[(node_name, sock)]['linger'] = ((0,0), 0)
         return (sockets[(node_name, sock)]['linger'][0], None)

      if (optname == SO_SNDLOWAT or optname == SO_RCVLOWAT):
	 raise SyscallWarning("setsockopt_syscall", 'ENOPROTOOPT', "[Application Error] \
               The option is unknown at the level indicated.")

      #if optname == SO_TYPE:
      #	 return (sockets[(node_name, sock)]['type'], None)


      if optname == SO_ACCEPTCONN:
	 if sockets[(node_name, sock)]['state'] == 'LISTEN':
	    return (0, None)
	 else:
	    return (-1, None)

      if optname == SO_KEEPALIVE:
	 if sockets[(node_name, sock)]['protocol'] == IPPROTO_TCP:
	    if 'keepalive' not in sockets[(node_name, sock)]:
	       sockets[(node_name, sock)]['keepalive'] = (0, 0)

	    return (sockets[(node_name, sock)]['keepalive'][0], None)
	 else:
	    return (-1, None)

      if optname == SO_SNDBUF:
	 return (sockets[(node_name, sock)]['sndbuf'][0], None)	 
	
      if optname == SO_RCVBUF:
	 return (sockets[(node_name, sock)]['rcvbuf'][0], None)

      if optname == SO_BROADCAST:
	 if 'broadcast' not in sockets[(node_name, sock)]:
	    sockets[(node_name, sock)]['broadcast'] = (0, 0)

	 return (sockets[(node_name, sock)]['broadcast'][0], None)

      if optname == SO_REUSEADDR:	 
	 if 'reuseaddr' not in sockets[(node_name, sock)]:
	    sockets[(node_name, sock)]['reuseaddr'] = (0, 0)

	 return (sockets[(node_name, sock)]['reuseaddr'][0], None)

      if optname == SO_REUSEPORT:
	 if 'reuseport' not in sockets[(node_name, sock)]:
	    sockets[(node_name, sock)]['reuseport'] = (0, 0)

	 return (sockets[(node_name, sock)]['reuseport'][0], None) 
      
      if optname == SO_OOBINLINE:
	 if 'oobdata' not in sockets[(node_name, sock)]:
	    sockets[(node_name, sock)]['oobdata'] = (0, 0)

	 return (sockets[(node_name, sock)]['oobdata'][0], None)

      if optname == SO_RCVTIMEO:
	 if 'recvtimeout' not in sockets[(node_name, sock)]:
	    sockets[(node_name, sock)]['recvtimeout'] = ("\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0", 0)

	 return (sockets[(node_name, sock)]['recvtimeout'][0], None)

      # For now return OK, but need to fix it
      else:
         raise SyscallNotice ("getsockopt_syscall", 'NOT_HANDLE_OPTION', "An option was given that the code does not handle.")

   else:
      raise SyscallNotice ("getsockopt_syscall", 'UNKNOWN_LEVEL', "We don't handle this level.")



# http://linux.die.net/man/2/getpeername
def getpeername_syscall(node_name, args, ret):
   
   sock, = args
   impl_ret, err = ret
   peer_addr, peer_port = impl_ret

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare ("getpeername_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   if sockets[(node_name, sock)]['peer_ip'] is not None:
      return ((sockets[(node_name, sock)]['peer_ip'], sockets[(node_name, sock)]['peer_port']), None)

   raise SyscallWarning("getpeername_syscall", 'ENOTCONN', "[Application Error] The descriptor is not connected.")



# http://linux.die.net/man/2/getsockname
def getsockname_syscall(node_name, args, ret):
   
   sock, = args
   impl_ret, err = ret
   addr, port = impl_ret

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare ("getsockname_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   socket = sockets[(node_name, sock)]

   if socket['state'] == 'CREATED':
      raise SyscallNotice ("getsockname_syscall", 'STATE_CREATED', "[Application Error] \
            No addr/port have been assigned to the socket, since it's only been created.")

   if socket['local_ip'] == None or IPAddress(socket['local_ip']).is_unspecified:
      sockets[(node_name, sock)]['local_ip'] = addr

   if socket['local_port'] == None or socket['local_port'] == 0:
      socket['local_port'] = port

   if socket['local_ip'] != addr or socket['local_port'] != port:
      raise SyscallWarning ("getsockname_syscall", 'BOUND_ADDR_DIFFERENT', "[Possible Network Misbehavior] \
            The IP addr that getsockname returns is different than the one that the socket is already bound to.")

   return ((addr, port), None)



# I'll work only on the operation that affect our model
# http://linux.die.net/man/2/fcntl
def fcntl_syscall(node_name, args, ret):

   sock = args[0]
   cmd = args[1]

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare ("fcntl_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")


   # I'm not sure we need to handle F_DUPFD_CLOEXEC

   if cmd == F_SETFL:
      arg = args[2]

      if arg & O_NONBLOCK != 0:
         sockets[(node_name, sock)]['nonblock'] = (1, 1)
      else:
         sockets[(node_name, sock)]['nonblock'] = (0, 1)

      return (0, None)

   else:
      raise SyscallNotice ("fcntl_syscall", 'NOT_HANDLE_OPTION', "An option was given that the code does not handle.")



# http://linux.die.net/man/2/ioctl   
def ioctl_syscall(node_name, args, ret):

   sock, command, value = args

   if (node_name, sock) not in active_sockets:
      raise SyscallDontCare ("ioctl_syscall", 'DONT_CARE', "The socket argument is not a valid file descriptor.")

   if command != 'FIONBIO':
      raise SyscallNotice ("ioctl_syscall", 'NOT_HANDLE_OPTION', "We aren't handling the command '" + command + "'.")

   if value != 0:
      sockets[(node_name, sock)]['nonblock'] = (1, 1)
   else:
      sockets[(node_name, sock)]['nonblock'] = (0, 1)

   return (0, None)




# if a fd is ready for reading, it's not necessary that we will have data for this fd, it may be ready to accept a connection
# in the opposite case though, aka if select returns timeout but there are data 'in the air' for this fd, it's a network error

# TODO: how I should handle writefds and should I take into consideration the timeout value??	 
# http://linux.die.net/man/2/select
def select_syscall(node_name, args, ret):
   
   readfds, writefds, errorfds, timeout = args
   ret1, ret2 = ret

   if ret1 == -1:
      raise SyscallDontCare ("select_syscall", 'DONT_CARE', "System call failed for some reason.")

   if not care_about_fd_list(node_name, readfds) or (type(ret1) != int and not care_about_fd_list(node_name, ret1)):
      raise SyscallDontCare ("poll_syscall", 'DONT_CARE', "None of the fds with events to be read are interesting.")

   if ret1 == 0 and ret2 == 'Timeout':
      for rfd in readfds:
         if (node_name, rfd) not in active_sockets:
            continue
         poll_timeout.add((node_name, rfd))

      for rfd in readfds:
         if (node_name, rfd) not in active_sockets:
            continue

         if sockets[(node_name, rfd)]['state'] == "LISTEN" and (node_name, rfd) in pending_connections and \
               pending_connections[(node_name, rfd)]:
            raise SyscallNotice("select_syscall", 'NETWORK_ERROR_%s%d' % (node_name, rfd), 
                  "[Possible Network Misbehavior] Avaliable connection but select sees nothing.")

	 for t in tcp_tuples:
	    if ((node_name, rfd) == t['accepting_fd'] and t['c_buffer'][1] != 0) or ((node_name, rfd) == t['connected_fd'] and t['a_buffer'][1] != 0):
	       raise SyscallWarning("select_syscall", 'NETWORK_ERROR_%s%d' % (node_name, rfd), 
                     "[Possible Network Misbehavior] Data 'in the air' but select sees nothing.")
      
	 for t in udp_tuples:

	    if (node_name, rfd) in t['accepting_fd_list'] and t['c_dtgrams'] != {}:
	       for dt in t['c_dtgrams']:
		  if t['c_dtgrams'][dt][1] < t['c_dtgrams'][dt][0]:
		     raise SyscallWarning("select_syscall", 'NETWORK_ERROR_%s%d' % (node_name, rfd), 
                           "[Possible Network Misbehavior] Data 'in the air' but select sees nothing.")

	    if (node_name, rfd) in t['connected_fd_list'] and t['a_dtgrams'] != {}:
	       for dt in t['a_dtgrams']:
		  if t['a_dtgrams'][dt][1] < t['a_dtgrams'][dt][0]:
		     raise SyscallWarning("select_syscall", 'NETWORK_ERROR_%s%d' % (node_name, rfd), 
                           "[Possible Network Misbehavior] Data 'in the air' but select sees nothing.")


	 #raise SyscallNotice("select_syscall", 'TIMEOUT_DETECTED', 'A time-out detected..')
	 poll_timeout.add((node_name, rfd))


   elif type(ret1) != int:

      for fd in ret1:
         # remove any entry from poll_timeout that does receive something
         if (node_name, fd) in poll_timeout:
            poll_timeout.remove((node_name, fd))

      for fd in ret1:

         # Disabling this since we can see connections ready to be accepted that we don't actually care about.
         #if sockets[(node_name, fd)]['state'] == "LISTEN" and not ((node_name, fd) in pending_connections and
         #      pending_connections[(node_name, fd)]):
         #   raise SyscallError("select_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd), "[Possible Network Misbehavior] No avaliable connections but select sees something.")

         for t in tcp_tuples:
            if (node_name, fd) == t['accepting_fd'] and t['c_buffer'][1] == 0 and \
                  not t['c_shutdown'] and t['connected_fd'] in active_sockets:
               raise SyscallError("select_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd),
                     "[Possible Network Misbehavior] No data 'in the air' but select sees something.")

            if (node_name, fd) == t['connected_fd'] and t['a_buffer'][1] == 0 and \
                  not t['a_shutdown'] and (t['accepting_fd'] is None or t['accepting_fd'] in active_sockets):
               raise SyscallError("select_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd),
                     "[Possible Network Misbehavior] No data 'in the air' but select sees something.")

         for t in udp_tuples:
            can_recv = False

            if (node_name, fd) in t['accepting_fd_list']:
               for dt in t['c_dtgrams']:
                  if t['c_dtgrams'][dt][1] < t['c_dtgrams'][dt][0]:
                     can_recv = True
                     break

            if not can_recv and (node_name, fd) in t['connected_fd_list']:
               for dt in t['a_dtgrams']:
                  if t['a_dtgrams'][dt][1] < t['a_dtgrams'][dt][0]:
                     can_recv = True
                     break

            if not can_recv:
               raise SyscallNotice("select_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd),
                     "[Possible Network Misbehavior] No data 'in the air' but select sees something.")

   return (ret1, ret2)


# http://linux.die.net/man/2/poll
def poll_syscall(node_name, args, ret):

   pollin, pollout, pollerr, timeout = args
   ret1, ret2 = ret

   if ret1 == -1:
      raise SyscallDontCare ("poll_syscall", 'DONT_CARE', "System call failed for some reason.")

   if not care_about_fd_list(node_name, pollin) or (type(ret1) != int and not care_about_fd_list(node_name, ret1[0])):
      raise SyscallDontCare ("poll_syscall", 'DONT_CARE', "None of the fds with events to be read are interesting.")

   if ret1 == 0 and ret2 == 'Timeout' and pollin != []:
      for fd in pollin:
         if (node_name, fd) not in active_sockets:
            continue
         poll_timeout.add((node_name, fd))

      for fd in pollin:
         if (node_name, fd) not in active_sockets:
            continue

         if sockets[(node_name, fd)]['state'] == "LISTEN" and (node_name, fd) in pending_connections and \
               pending_connections[(node_name, fd)]:
            raise SyscallNotice("select_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd), 
                  "[Possible Network Misbehavior] Avaliable connection but select sees nothing.")

	 for t in tcp_tuples:
	    if ((node_name, fd) == t['accepting_fd'] and t['c_buffer'][1] != 0) or ((node_name, fd) == t['connected_fd'] \
               and t['a_buffer'][1] != 0):
	       raise SyscallWarning("poll_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd), 
                     "[Possible Network Misbehavior] Data 'in the air' but poll sees nothing.")
      
	 for t in udp_tuples:
	    if (node_name, fd) in t['accepting_fd_list'] and t['c_dtgrams'] != {}:
	       for dt in t['c_dtgrams']:
		  if t['c_dtgrams'][dt][1] < t['c_dtgrams'][dt][0]:
		     raise SyscallWarning("poll_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd), 
                           "[Possible Network Misbehavior] Data 'in the air' but poll sees nothing.")


	    if (node_name, fd) in t['connected_fd_list'] and t['a_dtgrams'] != {}:
	       for dt in t['a_dtgrams']:
		  if t['a_dtgrams'][dt][1] < t['a_dtgrams'][dt][0]:
		     raise SyscallWarning("poll_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd), 
                           "[Possible Network Misbehavior] Data 'in the air' but poll sees nothing.")

	 poll_timeout.add((node_name, fd))
	 

   elif type(ret1) != int:

      for fd in ret1[0]:
         # remove any entry from poll_timeout that does receive something
         if (node_name, fd) in poll_timeout:
            poll_timeout.remove((node_name, fd))

      for fd in ret1[0]:

         # Disabling this since we can see connections ready to be accepted that we don't actually care about.
         #if sockets[(node_name, fd)]['state'] == "LISTEN" and not ((node_name, fd) in pending_connections and
         #      pending_connections[(node_name, fd)]):
         #   raise SyscallError("poll_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd), "[Possible Network Misbehavior] No avaliable connections but poll sees something.")

         for t in tcp_tuples:
            if (node_name, fd) == t['accepting_fd'] and t['c_buffer'][1] == 0 and \
                  not t['c_shutdown'] and t['connected_fd'] in active_sockets:
               raise SyscallError("select_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd),
                     "[Possible Network Misbehavior] No data 'in the air' but select sees something.")

            if (node_name, fd) == t['connected_fd'] and t['a_buffer'][1] == 0 and \
                  not t['a_shutdown'] and (t['accepting_fd'] is None or t['accepting_fd'] in active_sockets):
               raise SyscallError("select_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd),
                     "[Possible Network Misbehavior] No data 'in the air' but select sees something.")

         for t in udp_tuples:
            can_recv = False

            if (node_name, fd) in t['accepting_fd_list']:
               for dt in t['c_dtgrams']:
                  if t['c_dtgrams'][dt][1] < t['c_dtgrams'][dt][0]:
                     can_recv = True
                     break

            if not can_recv and (node_name, fd) in t['connected_fd_list']:
               for dt in t['a_dtgrams']:
                  if t['a_dtgrams'][dt][1] < t['a_dtgrams'][dt][0]:
                     can_recv = True
                     break

            if not can_recv:
               raise SyscallNotice("poll_syscall", 'NETWORK_ERROR_%s%d' % (node_name, fd),
                     "[Possible Network Misbehavior] No data 'in the air' but poll sees something.")

   return (ret1, ret2)



def care_about_fd_list(node_name, fd_list):
   """
   Returns whether or not there are any interesting fds in the given list.
   """

   for fd in fd_list:
      if (node_name, fd) in active_sockets:
         if sockets[(node_name, fd)]['state'] != 'CREATED' and \
               (sockets[(node_name, fd)]['state'] != 'BINDED' or \
               sockets[(node_name, fd)]['protocol'] != IPPROTO_TCP):
            return True

   return False



##### System call mappings #####

SYSCALL_DICT = {
   'accept_syscall' :      accept_syscall,
   'bind_syscall' :        bind_syscall,
   'close_syscall' :       close_syscall,
   'connect_syscall' :     connect_syscall,
   'fcntl_syscall' :       fcntl_syscall,
   'getpeername_syscall' : getpeername_syscall,
   'getsockname_syscall' : getsockname_syscall,
   'getsockopt_syscall' :  getsockopt_syscall,
   'ioctl_syscall' :       ioctl_syscall,
   'listen_syscall' :      listen_syscall,
   'poll_syscall' :        poll_syscall,
   'read_syscall' :        read_syscall,
   'recv_syscall' :        recv_syscall,
   'recvfrom_syscall':     recvfrom_syscall,
   'recvmsg_syscall' :     recvmsg_syscall,
   'select_syscall' :      select_syscall,
   'send_syscall' :        send_syscall,
   'sendfile_syscall' :    sendfile_syscall,
   'sendmsg_syscall' :     sendmsg_syscall,
   'sendto_syscall' :      sendto_syscall,
   'setsockopt_syscall' :  setsockopt_syscall,
   'shutdown_syscall' :    shutdown_syscall,
   'socket_syscall' :      socket_syscall,
   'write_syscall' :       write_syscall,
   'writev_syscall' :      writev_syscall,
}

