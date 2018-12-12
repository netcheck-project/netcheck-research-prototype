"""
Steven Portzer
Start Date: 03/05/2013

Purpose: To provide an entry point for processing posix traces so we
can move the posix specific logic out of trace_ordering.py.

"""

import model_network_syscalls as model
import trace_ordering
import posix_output
import ip_matching
import sys


##### Model Configuration #####

# Inspect the send and receive calls made within traces to better match
# up TCP connections.
ENABLE_TCP_DATA_MATCHING = False


# System calls that received data over the network.
RECV_SYSCALLS = [
  "recv_syscall", "recvfrom_syscall", "recvmsg_syscall", "read_syscall"
]

# System calls that send data over the network.
SEND_SYSCALLS = [
  "send_syscall", "sendto_syscall", "sendmsg_syscall", "sendfile_syscall",
  "write_syscall", "writev_syscall"
]

# System calls whose relative ordering we care about across traces.
ORDERED_SYSCALLS = RECV_SYSCALLS + SEND_SYSCALLS + [
  "accept_syscall", "connect_syscall", "close_syscall", "implicit_close",
  "poll_syscall", "select_syscall", "shutdown_syscall", "listen_syscall",
  "getpeername_syscall"
]



def syscall_priority(node_name, name, args, ret):
  """
  Returns the priority of the system call. The lower the number, the
  higher the priority.
  """

  if name not in ORDERED_SYSCALLS:
    return 0
  
  if name == 'select_syscall':
    if model.care_about_fd_list(node_name, args[0]) and (isinstance(ret[0], int)
        or model.care_about_fd_list(node_name, ret[0])):
      return 1
    
    #PRR: Select system call now dependent on recv/read
    elif name in RECV_SYSCALLS:
      return 1
    
    else: # Don't care about the call
      return 0
    
  if name == 'poll_syscall':
    if model.care_about_fd_list(node_name, args[0]) and (isinstance(ret[0], int)
        or model.care_about_fd_list(node_name, ret[0][0])):
      return 1
    
    #PRR: Poll System call now dependent on recv/read
    elif name in RECV_SYSCALLS:
      return 1
    
    else: # Don't care about the call
      return 0
    
  # Make sure the socket is one we care about.
  sock = (node_name, args[0])
  if sock not in model.active_sockets:
    return 0

  socket = model.sockets[sock]
  
  # Make sure if there is a remote address involved that we care about it.
  ip, port = None, None
  if name == 'accept_syscall':
    fd, ip, port = args
    
  elif name == 'recvfrom_syscall':
    sock, msg, buf_len, flags, ip, port = args
    
  elif name == 'recvmsg_syscall':
    sock, msg, buf_len, ip, port, flags = args
    
  elif name == 'connect_syscall':
    sock, ip, port = args
    
  elif name == 'sendto_syscall':
    sock, msg, flags, ip, port = args
    
  elif name == "sendmsg_syscall":
    sock, msg, ip, port, flags = args
    
  if not ip and socket['protocol'] == model.IPPROTO_UDP and name in SEND_SYSCALLS:
    ip, port = socket['peer_ip'], socket['peer_port']
    
  if ip and ip not in model.broadcast_ip and ip_matching.addr_dont_care(ip, port):
    return 0
  
  # We care about these calls, so now order them according to our rules.
  if name == 'accept_syscall':
    return 1
  
  elif name in RECV_SYSCALLS:
    return 1
  
  elif name == 'connect_syscall':
    if socket['protocol'] == model.IPPROTO_UDP:
      return 0
    return 2
  
  elif name in SEND_SYSCALLS:
    return 2

  #PRR: getpeername now has a lower priority - dependent on close
  elif name == 'listen_syscall' or name == 'getpeername_syscall':
    return 3
  
  elif name == "close_syscall" or name == "shutdown_syscall":
    if socket['state'] not in ['CONNECTED', 'LISTEN']:
      return 0
    return 3
  
  raise Exception("Failed to handle priority of " + name)



def main():
  """
  Entry point for processing posix traces for ordering.
  """

  trace_dict = None

  if len(sys.argv) >= 2 and sys.argv[1] == '-u':
    trace_filenames = sys.argv[2:]
    trace_dict = ip_matching.initialize_unit_test(trace_filenames,
        ENABLE_TCP_DATA_MATCHING)

  elif len(sys.argv) == 2:
    config_filename = sys.argv[1]
    trace_dict = ip_matching.initialize_hosts(config_filename,
        ENABLE_TCP_DATA_MATCHING)

  else:
    print "usage: python posix_ordering.py CONFIG_FILE"
    return

  try:
    posix_output.initialize_output(trace_dict.keys())
    trace_ordering.verify_traces(trace_dict, model.SYSCALL_DICT, syscall_priority)

  except trace_ordering.OrderingFailedException, err:
    posix_output.analyze_results(err.syscall_err_list)

  else:
    posix_output.analyze_results()


if __name__ == "__main__":
  main()

