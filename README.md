This is a brief overview of what all the different modules do and how
they work together. In order to run NetCheck, you need to write a
configuration file in order to tell NetCheck where to find the trace
files and how the network is configured. Consult example_config.txt for
information on how to write configuration files. Traces can then be
verified by running: python trace_ordering.py CONFIGURATION_FILE



lind_fs_constants / lind_net_constants
------------------------------------------------------------------------
Defines a lot of constants used by posix_test_harness_functions.


posix_test_harness_functions
------------------------------------------------------------------------
Reads in strace output file and returns tuples for system calls that can
affect the network or open file descriptors. Responsible for converting
strace output into easily usable data structures. Can be used either to
read the next system call from a file or to read in the entire trace.


posix_preprocessor
------------------------------------------------------------------------
Uses generators to wrap the output of posix_test_harness_functions. This
means that the returned "traces" are actually reading and parsing lines
as they are needed instead of trying to read the entire trace into
memory. The module also has a preprocessor that tracks which file
descriptors are duplicates of each other and outputs a "trace" (again,
actually a generator) with the property that each socket is uniquely
indentified by a single file descriptor. Calls like clone and dup are
stripped from the trace since they are already handled by the
preprocessor, and close calls are removed if they close a duplicate
file descriptor and not the actually socket.


ipaddr
------------------------------------------------------------------------
A library we are using for processing IPv4 and IPv6 addresses. Taken
from http://code.google.com/p/ipaddr-py/.


ip_matching
------------------------------------------------------------------------
Handles loading traces from configuration files and comparing addresses
based on the network configuration defined by the configuration file.
As part of this matching, it also identifies properties of possible
connections that the user should be aware of, like traversing a NAT,
connecting to 0.0.0.0, or connecting to an IPv6 address from an IPv4
address. Uses ipaddr extensively for indentifying properties of IP
addresses and uses posix_preprocessor to load preprocessed trace files.


model_network_syscalls
------------------------------------------------------------------------
This is where most of the actually processing occurs. Contains funtions
for all the network related systems calls that we care about and
simulates the results of invoking the system calls based on the current
model state. Uses ip_matching to determine which socket pairs
correspond to network connections.


posix_ordering
------------------------------------------------------------------------
Used to run configuration files. Takes the name of a configuration file
as its only argument and feeds this name into ip_matching to initialize
the network configuration and get back a list of traces to verify. Then
the module uses trace_ordering to perform the ordering.
Uses posix_output for logging results.


posix_output
------------------------------------------------------------------------
This is where I've been moving all the logging functionality from
posix_ordering. It also now handles generating some statistic and
warnings based on the exceptions raised by the model over the course of
its execution and the final state of the model.


trace_ordering
------------------------------------------------------------------------
Used to order traces. This and trace_output are the two non posix
specific files. Uses trace_output for logging results.


trace_output
------------------------------------------------------------------------
Contains a number of useful function for logging ordering results.

