"""
Steven Portzer
Start Date: 08/13/2012

Purpose: To generate analysis the result of POSIX trace ordering
and output statistics and possible issues

"""

import trace_ordering
import trace_output

import model_network_syscalls as model
from ip_matching import format_addr
from ip_matching import addr_dont_care
from ip_matching import is_addr_match



##### Output Level Configuration #####

# Print all the details of the model's state once verificantion finishes
PRINT_MODEL_STATE = False

# Print general statistics on the amount of data sent/received
PRINT_STATISTICS = True

######################################



# System calls that received data over the network.
RECV_SYSCALLS = [
  "recv_syscall", "recvfrom_syscall", "recvmsg_syscall", "read_syscall"
]

# System calls that send data over the network.
SEND_SYSCALLS = [
  "send_syscall", "sendto_syscall", "sendmsg_syscall", "sendfile_syscall",
  "write_syscall", "writev_syscall"
]



# Exceptions that occur during execution of the traces.
exception_list = []

# Ignored connect calls
dontcare_connect_list = []

# Ignored accept calls
dontcare_accept_list = []

# Maps sockets to the number of time that socket tried to write and got EPIPE or ECONNRESET
send_after_closed_dict = {}

# A dict of booleans specifying which traces have had network traffic we care about
trace_has_traffic = {}

# A dict of booleans specifying which traces have had network traffic we don't care about
has_dontcare_traffic = {}



def wrap_log_syscall():
  """
  Wraps log_syscall in trace_output to do additional postprocessing on each
  completed system call. There's probably a better way of doing this...
  """

  old_log_syscall = trace_output.log_syscall

  def wrapped_log_syscall(trace_id, syscall, err=None):

    old_log_syscall(trace_id, syscall, err)

    name, args, ret = syscall
    postprocess_syscall(trace_id, name, args, ret, err)

  trace_output.log_syscall = wrapped_log_syscall



def initialize_output(trace_ids):
  """
  Initializes the module for processing traces with the given trace IDs.
  """

  for trace_id in trace_ids:
    trace_has_traffic[trace_id] = False
    has_dontcare_traffic[trace_id] = False

  wrap_log_syscall()



def postprocess_syscall(trace_id, name, args, ret, err=None):
  """
  Saves information related to certain system calls to aid later
  analysis of the traces.
  """

  syscall_tuple = (trace_id, name, args, ret, err)

  sock_id = None
  sock = None

  # Find the socket in the posix model
  if name in RECV_SYSCALLS or name in SEND_SYSCALLS or \
      name == "accept_syscall" or name == "connect_syscall":
    sock_id = (trace_id, args[0])
    if sock_id in model.sockets:
      sock = model.sockets[sock_id]

  if err is None:

    # Keep track of which traces successfully send / recv data
    if sock and (name != "connect_syscall" or sock['protocol'] == model.IPPROTO_TCP):
      trace_has_traffic[trace_id] = True

    # Look for sockets that send data after the other side of the connection
    # closed the connection.
    if name in SEND_SYSCALLS and (ret == (-1, 'EPIPE') or ret == (-1, 'ECONNRESET')):
      send_after_closed_dict.setdefault(sock_id, 0)
      send_after_closed_dict[sock_id] += 1

  elif isinstance(err, trace_ordering.SyscallDontCare):
    # Keep track of accept and connect calls that get ignored by the model
    if name == 'connect_syscall':
      dontcare_connect_list.append(syscall_tuple)
    elif name == 'accept_syscall':
      dontcare_accept_list.append(syscall_tuple)

    # Keep track of which traces send / recv data that the model ignores
    if sock and (name != "connect_syscall" or sock['protocol'] == model.IPPROTO_TCP):
      has_dontcare_traffic[trace_id] = True

  elif isinstance(err, trace_ordering.SyscallException):
    # Maintain a list of all exceptions that occur
    exception_list.append(syscall_tuple)

    if err.args[1] == 'EPIPE/ECONNRESET':
      send_after_closed_dict.setdefault(sock_id, 0)
      send_after_closed_dict[sock_id] += 1



def analyze_results(syscall_err_list=None):
  """
  Prints a summary of trace ordering results. If ordering failed then
  syscall_err_list is a list of (trace_id, syscall, err) tuples for the
  system calls the ordering blocked on.
  """

  if syscall_err_list:
    for trace_id, syscall, err in syscall_err_list:
      name, args, ret = syscall
      exception_list.append((trace_id, name, args, ret, err))

  parsing_failed = False
  if syscall_err_list:
    parsing_failed = True

  # A list of strings, each corresponding to an issue encountered while
  # ordering the traces
  errors = []

  if parsing_failed:
    errors.append("The model failed to process the entire trace")

  if PRINT_MODEL_STATE:
    print_model_state()

  errors += check_possible_nats(parsing_failed)
  errors += check_tcp_buffers()
  errors += check_udp_buffers()
  errors += check_exceptions()

  print
  print "-" * 80
  print "Possible Problems Detected"
  print "-" * 80
  for error in errors:
    print " * " + error

  if not errors:
    print " * None"
  else:
    print
    print "For more details, adjust the variables defined in trace_output.py" + \
          " and posix_output.py to change the level of output"



def check_possible_nats(parsing_failed):
  """
  Prints some information related to possible NATs and TCP connecting
  and/or accepting issues. Returns a list of strings summarizing the
  issues detected. The argument parsing_failed indicates whether we were
  able to order the entire traces.
  """

  errors = []

  possible_nats = False
  found_something = False
  accept_dict = {}
  connect_dict = {}

  for a_sock in model.pending_connections:
    for c_sock in model.pending_connections[a_sock][:]:
      if model.sockets[c_sock]['state'] != 'CONNECTED':
        model.pending_connections[a_sock].remove(c_sock)

  for trace_id, name, args, ret, err in dontcare_accept_list:
    if ret[0] != -1:
      sock_id = (trace_id, args[0])
      accept_dict.setdefault(sock_id, set()).add(args[1])

  ##### Unaccepted connections #####
  # If a TCP connection has unaccepted connections, then we take this as
  # an indicator that the connecting trace may be behind a NAT

  for a_sock in model.pending_connections:
    if model.pending_connections[a_sock]:
      print
      print "-" * 80
      print "Network Configuration Issues"
      print "-" * 80
      found_something = True
      break

  for a_sock in model.pending_connections:
    pending = model.pending_connections[a_sock]
    if not pending:
      continue

    # Figure out how many unaccepted connections we have from each origin
    pending_dict = {}
    for sock in pending:
      key = (sock[0], model.sockets[sock]['peer_ip'], model.sockets[sock]['peer_port'])
      pending_dict.setdefault(key, 0)
      pending_dict[key] += 1

    local_addr = format_addr(model.sockets[a_sock]['local_ip'], model.sockets[a_sock]['local_port'])

    print "TCP server socket %s%d" % a_sock, "(private address " + local_addr + ") has",
    print len(pending), "unaccepted connection(s)"
    for trace_id, ip, port in pending_dict:
      print " * There are", pending_dict[(trace_id, ip, port)], "unaccepted connection(s) from trace",
      print trace_id, "to", format_addr(ip, port)

    if a_sock in accept_dict:
      print " * This server socket ignored connections from these IPs:", ", ".join(accept_dict[a_sock])
      print " * The traces whose connections have not been accepted may be behind NATs"
      possible_nats = True
    else:
      errors.append("[Possible Network Misbehavior] Connections intended for the socket in trace " +
           str(a_sock[0]) + " listening on "  + local_addr + " may have been accepted elsewhere")
      if parsing_failed:
        print " * Since the traces could not be fully processed, this alone may not be significant"
      print " * The connecting sockets may have connected to an entirely different server socket"

  ##### Ignored Accepts #####
  # If a TCP accepts a connection but there's no corresponding connect to
  # match it with, then this may mean the server is behind something

  # These are all the accept calls where the implementation succeeded but
  # the model fails to find a matching connection
  ignored_accepts = [(trace_id, args[0], args[1]) for trace_id, name, args, ret, err in exception_list
                     if err.args[1] == 'NO_PENDING_CONN' and ret[0] != -1]

  if ignored_accepts:
    print
    if not found_something:
      print "-" * 80
      print "Network Configuration Issues"
      print "-" * 80
    possible_nats = True
    found_something = True

  ignored_accept_dict = {}
  for trace_id, sock, peer_addr in ignored_accepts:
    ignored_accept_dict.setdefault((trace_id, sock), []).append(peer_addr)

  for a_sock in ignored_accept_dict:
    local_addr = format_addr(model.sockets[a_sock]['local_ip'], model.sockets[a_sock]['local_port'])
    print "TCP server socket %s%d (private address" % a_sock,
    print local_addr + ") failed to find corresponding connects for",
    print len(ignored_accept_dict[a_sock]), "accept(s)"

    # Count the number of unmatches accepts for each origin
    ignored_ip_dict = {}
    for ip in ignored_accept_dict[a_sock]:
      ignored_ip_dict.setdefault(ip, 0)
      ignored_ip_dict[ip] += 1

    for ip in ignored_ip_dict:
      print " * There are", ignored_ip_dict[ip], "unmatched accepts from IP", ip

    print " * Trace", a_sock[0], "may be behind a NAT and port forwarding may be occurring"

  ##### Connect Failure #####
  # If connect fails for some nonstandard reason, that that could indicate
  # somthing unusual filtering network connection

  unknown_connect_failures = [(trace_id, args) for trace_id, name, args, ret, err in exception_list
                              if err.args[1] == 'UNEXPECTED_FAILURE' and
                                 name == 'connect_syscall']

  if unknown_connect_failures:
    print
    if not found_something:
      print "-" * 80
      print "Network Configuration Issues"
      print "-" * 80
    found_something = True
    errors.append("[Possible Network Misbehavior] One or more connects failed with an unknown error. " + \
                  "This may be due to something filtering connection, for example a firewall.")

  unknown_connect_dict = {}
  for trace_id, args in unknown_connect_failures:
    sock, ip, port = args
    connect_tuple = (trace_id, (ip, port))
    unknown_connect_dict.setdefault(connect_tuple, 0)
    unknown_connect_dict[connect_tuple] += 1

  for trace, connect_addr in unknown_connect_dict:
    print "Trace", trace, "failed to connect to", format_addr(connect_addr[0], connect_addr[1]),
    print unknown_connect_dict[(trace, connect_addr)], "time(s) with an unknown error"
    for a_sock in model.sockets:
      if model.sockets[a_sock]['state'] != 'LISTEN':
        continue
      ip = model.sockets[a_sock]['local_ip']
      port = model.sockets[a_sock]['local_port']
      is_match, warnings = is_addr_match(a_sock[0], (ip, port), trace, connect_addr, True)
      if is_match:
        print "   This address matches server socket %s%d, which was bound to" % a_sock, format_addr(ip, port)
        for warning in warnings:
          print "    * [Warning]", warning

  ##### Connect Failure #####
  # If a connection is refused then that's also interesting data, especially
  # if it was trying to connect to an address that was being listened on

  refused_connect_failures = [(trace_id, args) for trace_id, name, args, ret, err in exception_list
                              if err.args[1] == 'ECONNREFUSED' and
                                 name == 'connect_syscall']

  if refused_connect_failures:
    print
    if not found_something:
      print "-" * 80
      print "Network Configuration Issues"
      print "-" * 80
    found_something = True

  refused_connect_dict = {}
  for trace_id, args in refused_connect_failures:
    sock, ip, port = args
    connect_tuple = (trace_id, (ip, port))
    refused_connect_dict.setdefault(connect_tuple, 0)
    refused_connect_dict[connect_tuple] += 1

  refused_issue = False

  for trace, connect_addr in refused_connect_dict:
    print "Trace", trace, "failed to connect to", format_addr(connect_addr[0], connect_addr[1]),
    print refused_connect_dict[(trace, connect_addr)], "time(s) because the connection was refused"
    for a_sock in model.sockets:
      if model.sockets[a_sock]['state'] != 'LISTEN':
        continue
      ip = model.sockets[a_sock]['local_ip']
      port = model.sockets[a_sock]['local_port']
      is_match, warnings = is_addr_match(a_sock[0], (ip, port), trace, connect_addr, True)
      if is_match:
        refused_issue = True
        print "   This address matches server socket %s%d, which was bound to" % a_sock, format_addr(ip, port)
        for warning in warnings:
          print "    * [Warning]", warning

  if refused_issue:
    errors.append("[Ambiguous Misbehavior] One or more connects to addresses " + \
                  "that were being listened on failed. This may be due to the " + \
                  "timing of the connect and listen or may be due to a network issue.")

  ##### Nonblocking Connect Failure #####
  # If a nonblocking connect never actually visibly connects, then that's
  # also interesting to note.

  failed_nonblock_connects = {}

  for sock in model.sockets:
    if model.sockets[sock]['state'] == 'PENDING' and \
        not addr_dont_care(model.sockets[sock]['peer_ip'], model.sockets[sock]['peer_port']):
      connect_tuple = (sock[0], model.sockets[sock]['peer_ip'], model.sockets[sock]['peer_port'])
      failed_nonblock_connects.setdefault(connect_tuple, 0)
      failed_nonblock_connects[connect_tuple] += 1

  if failed_nonblock_connects:
    print
    if not found_something:
      print "-" * 80
      print "Network Configuration Issues"
      print "-" * 80
    found_something = True
    print "Several nonblocking connects may have failed to connect"
    for trace, ip, port in failed_nonblock_connects:
      number = failed_nonblock_connects[(trace, ip, port)]
      print " *", number, "nonblocking connects from trace", trace, "to",
      print format_addr(ip, port), "were never observed to connect"

  ##### No Traffic #####
  # If a trace connects to a proxy, for example, then we will see traces
  # that have traffic, but not to an address we care about. If this happens
  # and we don't already have something more interesting to report as a
  # possible NAT indicator, then we will mention this.

  no_traffic = [trace_id for trace_id in trace_has_traffic
                if has_dontcare_traffic[trace_id] and not trace_has_traffic[trace_id]]

  if no_traffic and not found_something:
    print
    print "-" * 80
    print "Network Configuration Issues"
    print "-" * 80
    print "These traces have network activity, but do not appear to communicate with other traces:", ", ".join(no_traffic)
    if parsing_failed:
      print " * Since the traces could not be fully processed, this alone may not be significant"
    print " * This may indicate that they are behind a NAT"
    print " * It is also possible that there is a third party acting as a proxy or forwarding traffic"
    possible_nats = True

  if possible_nats:
    errors.append("There may be one or more NATs not declared in the configuration file")
    print
    print "Please check if there are any NATs present which are not explicitly declared in the configuration file"
    print " * If so, add them to configuration file and rerun NetCheck"

  return errors



def check_exceptions():
  """
  Prints some information related to miscellaneous errors and model
  exceptions that occurred. Returns a list of strings summarizing the
  issues detected.
  """

  unknown_calls = set()
  buffer_size_exceptions = {}
  option_not_handled_exceptions = 0
  overlapping_conns = set()

  connect_failed = []

  # Nothing too exciting here, just counting up the frequency of certain
  # unusual exceptions and reporting them.

  for trace_id, name, args, ret, err in exception_list:
    impl_ret, impl_err = ret
    model_err = err.args[1]

    if model_err == 'UNKNOWN_SYSCALL':
      unknown_calls.add(name)
    elif model_err == 'NOT_HANDLE_OPTION' or model_err == 'UNKNOWN_LEVEL':
      option_not_handled_exceptions += 1
    elif model_err == 'MSG_>_BUFSIZE':
      buffer_size_exceptions.setdefault(trace_id, 0)
      buffer_size_exceptions[trace_id] += 1
    elif model_err == 'OVERLAPPING_CONNECTS':
      overlapping_conns.add(trace_id)
    elif model_err == 'UNEXPECTED_SUCCESS':
      if name == 'connect_syscall':
        trace_id, sock, ip, port = args
        connect_failed.append((trace_id, ip, port, impl_err))

  errors = []

  for trace_id in buffer_size_exceptions:
    errors.append("[Possible Network Misbehavior] " + str(buffer_size_exceptions[trace_id]) +
        " different call(s) caused trace " + str(trace_id) + " to exceeded an expected buffer size")

  for trace_id, ip, port, impl_err in connect_failed:
    errors.append("[Possible Network Misbehavior] Trace " + trace_id + " unexpectedly failed to connect to "
         + format_addr(ip, port) + " with the following error: " + impl_err)

  if unknown_calls:
    errors.append("The following call(s) are not currently handled by the model: " + ", ".join(unknown_calls))

  if option_not_handled_exceptions:
    errors.append(str(option_not_handled_exceptions) +
        " call(s) to getsockopt, setsockopt, fcntl, or ioctl used options which are not currently handled")

  if overlapping_conns:
    if len(overlapping_conns) == 1:
      errors.append("Trace " + list(overlapping_conns)[0] +
          " has simultaneously occurring nonblocking connects, which may " +
          "mean that the corresponding accepts are improperly matched")
    else:
      errors.append("Trace(s) " + ", ".join(overlapping_conns) +
          " have simultaneously occurring nonblocking connects, which may " +
          "mean that the corresponding accepts are improperly matched")

  return errors



def check_tcp_buffers():
  """
  Prints some information related to issues with established TCP
  connections and optionally some TCP statistics. Returns a list of
  strings summarizing the issues detected.
  """

  for t in model.tcp_tuples:
    if t['accepting_fd'] is not None:
      break
  else:
    return []

  if PRINT_STATISTICS:
    print
    print "-" * 80
    print "TCP Connection Statistics"
    print "-" * 80

  nonempty_connection_dict = {}

  # Look for instances of poll/select reporting no data when there is
  # data to be received
  poll_errors = set([(trace_id, args[0]) for trace_id, name, args, ret, err in exception_list
                     if (err.args[0] == 'recv_syscall' or err.args[0] == 'send_syscall') and
                        err.args[1].startswith('NETWORK_ERROR')])

  for t in model.tcp_tuples:
    # Connection was never accepted
    if t['accepting_fd'] is None:
      continue 

    connect_sock = model.sockets[t['connected_fd']]
    accept_sock = model.sockets[t['accepting_fd']]
    connect_tuple = (t['connected_fd'][0], connect_sock['peer_ip'], connect_sock['peer_port'])

    # We are looking for connection where some data was never received,
    # and we want to distinguish between case where poll/select reported
    # no data when we expected there to be receivable data 
    if t['c_buffer'][1] != 0 or t['a_buffer'][1] != 0:
      event_tuple = connect_tuple + (t['connected_fd'] in poll_errors or
          t['accepting_fd'] in poll_errors,)
      nonempty_connection_dict.setdefault(event_tuple, 0)
      nonempty_connection_dict[event_tuple] += 1

    if PRINT_STATISTICS:
      print "Connection from socket %s%d (public address" % t['connected_fd'],
      print format_addr(accept_sock['peer_ip'], accept_sock['peer_port']) + ")",
      print "to socket %s%d (public address" % t['accepting_fd'],
      print format_addr(connect_sock['peer_ip'], connect_sock['peer_port']) + ")"

      print " * Data sent to accepting socket %s%d:" % t['accepting_fd'],
      print t['c_buffer'][2], "bytes sent,",
      print t['c_buffer'][2] - t['c_buffer'][1], "bytes received,",
      print t['c_buffer'][1], "bytes lost",
      if t['c_buffer'][1]:
        print "(%.2f%%)" % (100.0 * t['c_buffer'][1] / t['c_buffer'][2]),
      print

      print " * Data sent to connected socket %s%d:" % t['connected_fd'],
      print t['a_buffer'][2], "bytes sent,",
      print t['a_buffer'][2] - t['a_buffer'][1], "bytes received,",
      print t['a_buffer'][1], "bytes lost",
      if t['a_buffer'][1]:
        print "(%.2f%%)" % (100.0 * t['a_buffer'][1] / t['a_buffer'][2]),
      print

      if t['c_buffer'][1] != 0 or t['a_buffer'][1] != 0:
        if t['connected_fd'] in poll_errors or t['accepting_fd'] in poll_errors:
          print " * [Ambiguous Misbehavior] Data loss may be due to network conditions, such as filtering or network delay, but may also be due to delay in application itself"
        else:
          print " * [Possible Application Misbehavior] Data loss is most likely due to application behavior"

      if t['connected_fd'] in send_after_closed_dict:
        print " * [Possible Application Misbehavior] socket %s%d" % t['connected_fd'],
        print "failed to send some data because the connection was closed"

      if t['accepting_fd'] in send_after_closed_dict:
        print " * [Possible Application Misbehavior] socket %s%d" % t['accepting_fd'],
        print "failed to send some data because the connection was closed"

  errors = []

  for trace_id, ip, port, is_ambiguous in nonempty_connection_dict:
    if is_ambiguous:
      errors.append("[Ambiguous Misbehavior] Trace " + trace_id + " has " +
          str(nonempty_connection_dict[(trace_id, ip, port, is_ambiguous)]) + " TCP connection(s) to " +
          format_addr(ip, port) + " with unreceived data not detected by poll or select")
    else:
      errors.append("[Possible Application Misbehavior] Trace " + trace_id + " has " +
          str(nonempty_connection_dict[(trace_id, ip, port, is_ambiguous)]) + " TCP connection(s) to " +
          format_addr(ip, port) + " with data left in the buffers")

  return errors



def check_udp_buffers():
  """
  Prints some information related to issues with UDP communications and
  optionally some UDP statistics. Returns a list of strings summarizing
  the issues detected.
  """

  if not model.udp_tuples:
    return []

  connection_dict = {}

  # We care counting data sent and data lost per pair of addresses, and
  # we are tracking both total number of bytes sent/lost and total number
  # of messages sent/lost
  for t in model.udp_tuples:
    if t['connected_ip']:
      sender = (t['connected_ip'], t['connected_port'])
    else:
      # This is in case we have a UDP socket bound to an unknown address
      # sending messages
      sender = list(t['connected_fd_list'])[0][0]
    receiver = (t['accepting_ip'], t['accepting_port'])
    connect_tuple = (sender, receiver)
    accept_tuple = (receiver, sender)
    if connect_tuple not in connection_dict:
      connection_dict[connect_tuple] = {'sent': 0, 'lost': 0, 'bytes_sent': 0, 'bytes_lost': 0}
    if accept_tuple not in connection_dict:
      connection_dict[accept_tuple] = {'sent': 0, 'lost': 0, 'bytes_sent': 0, 'bytes_lost': 0}

    for m in t['a_dtgrams']:
      connection_dict[accept_tuple]['sent'] += t['a_dtgrams'][m][0]
      connection_dict[accept_tuple]['bytes_sent'] += t['a_dtgrams'][m][0] * len(m)
      unreceived = t['a_dtgrams'][m][0] - t['a_dtgrams'][m][1]
      if unreceived > 0:
        connection_dict[accept_tuple]['lost'] += unreceived
        connection_dict[accept_tuple]['bytes_lost'] += unreceived * len(m)

    for m in t['c_dtgrams']:
      connection_dict[connect_tuple]['sent'] += t['c_dtgrams'][m][0]
      connection_dict[connect_tuple]['bytes_sent'] += t['c_dtgrams'][m][0] * len(m)
      unreceived = t['c_dtgrams'][m][0] - t['c_dtgrams'][m][1]
      if unreceived > 0:
        connection_dict[connect_tuple]['lost'] += unreceived
        connection_dict[connect_tuple]['bytes_lost'] += unreceived * len(m)

  errors = []

  if PRINT_STATISTICS:
    print
    print "-" * 80
    print "UDP Traffic Statistics"
    print "-" * 80

    for sender, receiver in connection_dict:
      addr_dict = connection_dict[(sender, receiver)]

      if not addr_dict['sent']:
        continue

      if isinstance(sender, tuple):
        sender_str = format_addr(sender[0], sender[1])
      else:
        sender_str = "trace " + sender
      receiver_str = format_addr(receiver[0], receiver[1])

      print "Traffic from", sender_str, "to", receiver_str

      print " *",
      print addr_dict['sent'], "datagrams sent,",
      print addr_dict['sent'] - addr_dict['lost'], "datagrams received,",
      print addr_dict['lost'], "datagrams lost",
      if addr_dict['lost']:
        print "(%.2f%%)" % (100.0 * addr_dict['lost'] / addr_dict['sent']),
      print

      print " *",
      print addr_dict['bytes_sent'], "bytes sent,",
      print addr_dict['bytes_sent'] - addr_dict['bytes_lost'], "bytes received,",
      print addr_dict['bytes_lost'], "bytes lost",
      if addr_dict['bytes_lost']:
        print "(%.2f%%)" % (100.0 * addr_dict['bytes_lost'] / addr_dict['bytes_sent']),
      print

      # We only report an error in the trace summary if all datagrams were lost
      if addr_dict['lost'] == addr_dict['sent']:
        errors.append("[Possible Network Misbehavior] All " + str(addr_dict['sent']) +
            " datagrams sent from " + sender_str + " to " + receiver_str + " were lost")

  return errors



def print_model_state():
  """
  Prints the current state of the posix model.
  """

  print
  print "-" * 80
  print "Final Model State"
  print "-" * 80
  print "tcp_tuples:"
  for t in model.tcp_tuples:
    print "  ", t

  print
  print "udp_tuples:"
  for t in model.udp_tuples:
    print "  ", t

  print
  print "sockets:"
  for socket in model.sockets:
    print "  ",
    if socket in model.active_sockets:
      print "[ACTIVE]",
    print str(socket) + ":", model.sockets[socket]

  print
  print "pending_connections:", model.pending_connections
  print "poll_timeout:", list(model.poll_timeout)

