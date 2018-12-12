"""
Steven Portzer
Start Date: 07/26/2012

Purpose: Preprocess trace files so that file descriptors are unique
and not duplicated.

"""

import posix_test_harness_functions as parser
import sys

PF_INET = 2
PF_INET6 = 30

SOCK_STREAM = 1
IPPROTO_TCP = 6

MSG_PEEK = 0x2

CLONE_FILES = 0x400

F_DUPFD =  0

# System calls that received data over the network.
RECV_SYSCALLS = [
  "recv_syscall", "recvfrom_syscall", "recvmsg_syscall", "read_syscall"
]

# System calls that send data over the network.
SEND_SYSCALLS = [
  "send_syscall", "sendto_syscall", "sendmsg_syscall", "sendfile_syscall",
  "write_syscall", "writev_syscall"
]



def get_trace_from_file(file_obj):
  """
  A generator that iterates through the system calls in the given
  readabletrace trace file.
  """

  trace = []

  while True:
    trace += parser.getValidTraceLine(file_obj)

    if not trace:
      return
    while trace:
      yield trace.pop(0)



def get_trace_from_filename(filename):
  """
  A generator that iterates through the system calls in the trace file
  referenced by the given file name.
  """

  try:
    file_obj = open(filename, 'r')    
  except IOError, e:
    if e[0] == 2:  # error code 2: file does not exist
      print "'" + filename + "' is not at the correct location...exiting\n\n\
      'python posix_ordering.py CONFIG_FILE': trace file(s) should be at the same dir as CONFIG_FILE.\n\n\
      'python posix_ordering.py -u trace_file1 trace_file2 etc': trace file(s) should be at the same dir as posix_ordering.py.\n"
      sys.exit(0)      
    elif e[0] == 21:  # error code 21: it is a directory rather than a file
      print "'" + filename + "' is a directory...exiting\n"  
      sys.exit(0)
    else:  # for all other cases of IOError's, simply raise them
      raise        

  for syscall in get_trace_from_file(file_obj):
    yield syscall

  file_obj.close()



def preprocess_trace(trace, trace_id, print_warnings=True):
  """
  A generator that iterates through trace and rewrites the calls so
  file descriptors are replaced with ID numbers with a one-to-one
  correspondence to sockets we might care about and the pids are removed
  Clone, dup, and fcntl calls that duplicate file descriptors are handled
  by the preprocessor and not passed on in the generated trace. Only the
  close call that closes the last open reference to a socket is yielded.
  Any calls not relating to sockets we might care about are also stripped
  from the trace.
  """

  sock_counter = 0

  pid_map = {}
  fd_map = {}

  tcp_socks = set()
  sock_pid = {}

  concurrent_access_set = set()

  for name, args, ret in trace:
    real_pid = args[0]
    pid = pid_map.get(real_pid, real_pid)
    args = args[1:]

    # TODO: in cases where we create a file descriptor that we think is
    # already open, we should flag this somehow

    if name == 'socket_syscall':
      if args[0] != PF_INET and args[0] != PF_INET6:
        continue
      if ret[0] == -1:
        continue

      sock = sock_counter
      sock_counter += 1
      fd_map[(pid, ret[0])] = sock
      ret = (sock, None)

      if args[1] == SOCK_STREAM and (args[2] == IPPROTO_TCP or args[2] == 0):
        tcp_socks.add(sock)

    elif name == 'clone_syscall':
      if ret[0] != -1:
        if args[0] & CLONE_FILES != 0:
          pid_map[ret[0]] = pid
        else:
          for fd in fd_map.copy():
            if fd[0] == pid:
              fd_map[(ret[0], fd[1])] = fd_map[fd]
      continue

    elif name == 'select_syscall':
      readfds, writefds, errorfds, timeout = args

      new_readfds = []
      for fd in readfds:
        if (pid, fd) in fd_map:
          new_readfds.append(fd_map[(pid, fd)])

      new_writefds = []
      for fd in writefds:
        if (pid, fd) in fd_map:
          new_writefds.append(fd_map[(pid, fd)])

      new_errorfds = []
      for fd in errorfds:
        if (pid, fd) in fd_map:
          new_errorfds.append(fd_map[(pid, fd)])

      if not new_readfds and not new_writefds and not new_errorfds:
        continue

      args = new_readfds, new_writefds, new_errorfds, timeout

      if not isinstance(ret[0], int):
        r_in, r_out = ret

        new_r_in = []
        for fd in r_in:
          if (pid, fd) in fd_map:
            new_r_in.append(fd_map[(pid, fd)])

        new_r_out = []
        for fd in r_out:
          if (pid, fd) in fd_map:
            new_r_out.append(fd_map[(pid, fd)])

        if not new_r_in and not new_r_out:
          continue

        ret = new_r_in, new_r_out

    elif name == 'poll_syscall':
      pollin, pollout, pollerr, timeout = args

      new_pollin = []
      for fd in pollin:
        if (pid, fd) in fd_map:
          new_pollin.append(fd_map[(pid, fd)])

      new_pollout = []
      for fd in pollout:
        if (pid, fd) in fd_map:
          new_pollout.append(fd_map[(pid, fd)])

      new_pollerr = []
      for fd in pollerr:
        if (pid, fd) in fd_map:
          new_pollerr.append(fd_map[(pid, fd)])

      if not new_pollin and not new_pollout and not new_pollerr:
        continue

      args = new_pollin, new_pollout, new_pollerr, timeout

      if not isinstance(ret[0], int):

        r_in, r_out, r_err = ret[0]

        new_r_in = []
        for fd in r_in:
          if (pid, fd) in fd_map:
            new_r_in.append(fd_map[(pid, fd)])

        new_r_out = []
        for fd in r_out:
          if (pid, fd) in fd_map:
            new_r_out.append(fd_map[(pid, fd)])

        new_r_err = []
        for fd in r_err:
          if (pid, fd) in fd_map:
            new_r_err.append(fd_map[(pid, fd)])

        if not new_r_in and not new_r_out and not new_r_err:
          continue 

        ret = ((new_r_in, new_r_out, new_r_err), None)

    else:
      fd = (pid, args[0])

      if name == 'dup_syscall' or name == 'dup2_syscall' or \
          (name == 'fcntl_syscall' and args[1] == F_DUPFD):
        if ret[0] != -1 and ret[0] != args[0]:
          new_fd = (pid, ret[0])
          if new_fd in fd_map:
            old_sock = fd_map[new_fd]
            del fd_map[new_fd]
            if old_sock not in fd_map.values():
              yield ('close_syscall', (old_sock,), (0, None))
          if fd in fd_map:
            fd_map[new_fd] = fd_map[fd]
        continue

      if fd not in fd_map:
        continue

      sock = fd_map[fd]
      args = (sock,) + args[1:]

      if name in SEND_SYSCALLS or name in RECV_SYSCALLS or name == 'shutdown_syscall':
        if sock in sock_pid and sock_pid[sock] != real_pid:
          # TODO: integrate this into trace_output maybe
          if print_warnings and sock not in concurrent_access_set:
            concurrent_access_set.add(sock)
            print ("[Warning] TCP socket %s%d is being used for " +
                "network operations by multiple threads") % (trace_id, sock)

        if sock in tcp_socks:
          sock_pid[sock] = real_pid

      if name == 'close_syscall':
        del fd_map[fd]
        # Only print a warning if two threads share the same file descriptor
        # table so one thread closes the fd for both of them, and the other
        # thread was using the socket for network operations.
        if sock in sock_pid and sock_pid[sock] != real_pid and \
            pid_map.get(sock_pid[sock], sock_pid[sock]) == pid:
          if print_warnings:
            print ("[Warning] TCP socket %s%d was closed by a different " +
                "thread than the one using it for network operations") % (trace_id, sock)
        if sock in fd_map.values():
          continue

      elif name == 'accept_syscall':
        if ret[0] != -1:
          new_sock = sock_counter
          sock_counter += 1
          fd_map[(pid, ret[0])] = new_sock
          ret = (new_sock, None)
          tcp_socks.add(new_sock)

    yield (name, args, ret)

  # Do implicit closes for all currently open sockets.
  for sock in set(fd_map.values()):
    yield ('close_syscall', (sock,), (0, None))



def get_sock_data(trace_id, trace):
  """
  Takes a trace and returns (connect_sock_list, accept_sock_list), where
  both lists contain dictionaries containing sent and received data for
  TCP sockets communicating within the trace.
  """

  tcp_sockets = {}
  connected_set = set()
  connect_sock_list = []
  accept_sock_list = []

  for name, args, ret in trace:

    impl_ret, impl_err = ret

    if impl_ret == -1:
      continue

    elif name == 'socket_syscall':
      dom, typ, prot = args
      if typ == SOCK_STREAM and (prot == IPPROTO_TCP or prot == 0):
        tcp_sockets[impl_ret] = {'name': (trace_id, impl_ret),
                                 'sndbuf': '', 'rcvbuf': '',
                                 'sndlen': 0, 'rcvlen':0}

    elif name == 'accept_syscall':
      sock, ip, port = args
      if sock not in tcp_sockets:
        continue
      sock_state = {'name': (trace_id, impl_ret),
                    'sndbuf': '', 'rcvbuf': '',
                    'sndlen': 0, 'rcvlen':0}
      tcp_sockets[impl_ret] = sock_state
      connected_set.add(impl_ret)
      accept_sock_list.append(sock_state)

    elif name == 'connect_syscall':
      sock, ip, port = args
      if sock not in tcp_sockets:
        continue
      if sock not in connected_set:
        connected_set.add(sock)
        connect_sock_list.append(tcp_sockets[sock])

    elif name in RECV_SYSCALLS:
      if args[1] not in tcp_sockets:
        continue

      flags = 0

      if name == 'recvfrom_syscall':
        sock, msg, buf_len, flags, ip, port = args

      elif name == "recvmsg_syscall":
        sock, msg, buf_len, ip, port, flags = args

      elif name == 'recv_syscall':
        sock, msg, buf_len, flags = args

      elif name == 'read_syscall':
        sock, msg, buf_len = args

      if impl_ret < 0 or flags == MSG_PEEK:
        continue

      msg = msg.decode('string_escape')

      if sock not in connected_set:
        connected_set.add(sock)
        connect_sock_list.append(tcp_sockets[sock])

      if len(tcp_sockets[sock]['rcvbuf']) == tcp_sockets[sock]['rcvlen']:
        tcp_sockets[sock]['rcvbuf'] += msg[:impl_ret]
      tcp_sockets[sock]['rcvlen'] += impl_ret

    elif name in SEND_SYSCALLS:
      if args[0] not in tcp_sockets:
        continue

      flags = 0
      msg = ''

      if name == 'send_syscall':
        sock, msg, flags = args

      elif name == 'write_syscall':
        sock, msg = args

      elif name == 'writev_syscall':
        sock, msg, count = args

      elif name == 'sendto_syscall':
        sock, msg, flags, ip, port = args

      elif name == "sendmsg_syscall":
        sock, msg, ip, port, flags = args

      elif name == "sendfile_syscall":
        sock, in_sock, offset, count = args

      if impl_ret < 0:
        continue

      msg = msg.decode('string_escape')

      if sock not in connected_set:
        connected_set.add(sock)
        connect_sock_list.append(tcp_sockets[sock])

      if len(tcp_sockets[sock]['sndbuf']) == tcp_sockets[sock]['sndlen']:
        tcp_sockets[sock]['sndbuf'] += msg[:impl_ret]
      tcp_sockets[sock]['sndlen'] += impl_ret

  return connect_sock_list, accept_sock_list



if __name__ == "__main__":
  import sys
  for syscall in preprocess_trace(get_trace_from_filename(sys.argv[1]), ''):
    print syscall
