
from net import client,server
from Crypto.Hash import SHAKE128
class Virtualbuffer:
    '''
    optimistic will apply to udp - don't request ACK
    live-local write to disk the moment u recive object not only after connection loss or on exit
    '''
    def __init__(self,passive_sync=True,passive_sync_interval=60,passive_sync_optimistic=True,max_buffer_size=1024*1024,max_waiting_objects=8,live_local=False,local_dir=None): 
        pass

    def sync():
        pass

 