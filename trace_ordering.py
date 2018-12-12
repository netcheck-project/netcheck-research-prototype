"""
Steven Portzer
Start Date: 07/1/2012

Purpose: To order system calls from traces collected across multiple trace.

"""

import trace_output


###### Exception Classes 

class SyscallException(Exception):
   """
   An exception raised by the model. Arguments are expected to be of the
   form syscall_name, error_name, explaination_string.
   """

class SyscallError(SyscallException):
   """
   A system call would result in an error that should match an error
   raised by the implementation.
   """

class SyscallWarning(SyscallException):
   """
   A system call would result in an error, but we can't do anything
   about it so we should continue regardless.
   """

class SyscallNotice(SyscallException):
   """
   A system call would result in some sort of problem, but it's not
   particular severe we can't do anything about it so we should continue.
   """

class SyscallDontCare(SyscallException):
   """
   We don't care about this system call.
   """


class OrderingFailedException(Exception):
  """
  No valid ordering of the system calls was found.
  """

  def __init__(self, string, syscall_err_list):
    self.syscall_err_list = syscall_err_list
    Exception.__init__(self, string)



def verify_traces(trace_dict, model, priority=None):
  """
  <Purpose>
    Attempts to produce a valid ordering of the traces.

  <Arguments>
    trace_dict:
      A dictionary mapping trace IDs to iterable objects that yield
      (syscall_name, args, ret) tuples.
    model:
      A dictionary mapping syscall names to functions of the form
      syscall_name(trace_id, args, ret) that return expected ret values.
    priority:
      If specified, a function priority(trace_id, syscall_name, args, ret)
      that returns numerical values. The lower the value, the more we prefer
      to consume that system call.

  <Exceptions>
    OrderingFailedException if no valid ordering is found.

  <Returns>
    None.
  """

  trace_output.log_intialize()

  traces_iter_dict = {}
  for trace_id in trace_dict:
    traces_iter_dict[trace_id] = iter(trace_dict[trace_id])

  syscall_dict = {}

  for trace_id in traces_iter_dict:
    try:
      syscall_dict[trace_id] = traces_iter_dict[trace_id].next()
    except StopIteration:
      pass

  while syscall_dict:
    next_syscall_id = choose_next_syscall(syscall_dict, model, priority)

    try:
      syscall_dict[next_syscall_id] = traces_iter_dict[next_syscall_id].next()
    except StopIteration:
      del syscall_dict[next_syscall_id]

  trace_output.log_done()


def another_action_from_this_flow_is_queued(matchingitem, syscall_list):

  for item in syscall_list:

    # skip up
    if item is matchingitem:
      continue
    
    # Is this action from the same flow?
    if item['peer_ip'] == matchingitem['local_ip'] and item['peer_port'] == matchingitem['local_port'] and matchingitem['peer_ip'] == item['local_ip'] and matchingitem['peer_port'] == item['local_port'] and domain, type, protocol are the same...
      return True

  # could not find a matching flow
  return False




def choose_next_syscall(syscall_dict, model, priority=None):
  """
  <Purpose>
    Takes a list of system call tuples and decides which of these calls
    to do next.

  <Arguments>
    syscall_dict:
      A dictionary mapping trace IDs to (syscall_name, args, ret) tuples
      that we should choose between.
    model:
      A dictionary mapping syscall names to functions of the form
      syscall_name(trace_id, args, ret) that return expected ret values.
    priority:
      If specified, a function priority(trace_id, syscall_name, args, ret)
      that returns numerical values. The lower the value, the more we prefer
      to consume that system call.

  <Exceptions>
    OrderingFailedException if no valid ordering is found.

  <Returns>
    The trace ID of the chosen system call.
  """

  syscall_list = syscall_dict.items()

  # Sort the system calls based on priority.
  if priority:
    def syscall_key(item):
      trace_id, syscall = item
      name, args, ret = syscall
      if another_action_from_this_flow_is_queued(item, syscall_list):
        # another item is queued for this flow (#XX)
        return priority(trace_id, name, args, ret)
      else:  
        # this is the only one.   Drop the priority by 100 to stick it at
        # the end
        return priority(trace_id, name, args, ret) + 100

    syscall_list.sort(key=syscall_key)

  syscall_err_list = []

  for trace_id, syscall in syscall_list:
    try:
      model_call(trace_id, syscall, model)

    # We can't continue past errors.
    except SyscallError, err:
      trace_output.log_syscall_attempt(trace_id, syscall, err)
      syscall_err_list.append((trace_id, syscall, err))

    # Other exceptions should be logged, but we shouldn't try to
    # execute the call again.
    except SyscallException, err:
      trace_output.log_syscall(trace_id, syscall, err)
      return trace_id

    # The call succeeded without any unusual behavior.
    else:
      trace_output.log_syscall(trace_id, syscall)
      return trace_id

  # We can't do anything, so ordering failed
  trace_output.log_execution_blocked(syscall_err_list)
  raise OrderingFailedException("No valid action found.", syscall_err_list)



def model_call(trace_id, syscall, model):
  """
  <Purpose>
    Tries to execute a system call.

  <Arguments>
    trace_id:
      A identifier for the trace the system call belongs to.
    syscall:
      A (syscall_name, args, ret) tuple to execute.
    model:
      A dictionary mapping syscall names to functions of the form
      syscall_name(trace_id, args, ret) that return expected ret values.

  <Exceptions>
    SyscallException if the system call causes the model to raise an
      exception or misbehave.

  <Returns>
    None.
  """

  name, args, ret = syscall
  impl_ret, impl_errno = ret

  try:
    if name in model:
      model_ret = model[name](trace_id, args, ret)
    else:
      # This system call isn't in our model.
      raise SyscallNotice(name, 'UNKNOWN_SYSCALL', "'" + name + "' is not a recognized system call.")

  # If the error raised by the model matches the error raised by the
  # implementation, then we can continue. Otherwise, we can't continue
  # past this system call.
  except SyscallError, err:
    if impl_ret == -1 and isinstance(impl_errno, str) and impl_errno in err.args[1]:
      return
    raise err

  # The model shouldn't be able to succeed if the implementation raised
  # an error, but we can't backtrack so we will continue past this call.
  if impl_ret == -1:
    raise SyscallWarning(name, 'UNEXPECTED_SUCCESS', "Model succeeded but implementation failed.")

  # The model should return the same result as the implementation, but
  # we can't backtrack so we will continue past this call.
  if impl_ret != model_ret[0]:
    raise SyscallWarning(name, 'UNEXPECTED_RETURN_VALUE', "Model returned " + str(model_ret[0]))


