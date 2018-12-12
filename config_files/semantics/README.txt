The other semantics tests can be validated using a special unit test flag:
python trace_ordering.py -u TRACEFILE [...]
You can list as many trace files as you want, and NetCheck will assume that all
traces were collected on the same machine and only communicate over loopback.
