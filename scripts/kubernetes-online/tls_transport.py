"""Owned opaque TLS pass-through and bounded server-ciphertext delay controls.
The proxy never decrypts TLS, replaces certificates, edits HTTP or retries a
request on an established connection. Both production adapters authenticate the
original API-server certificate and independently verify the upstream authority.
"""
import socket
import threading
import time

class OpaqueTlsTransport:
    def __init__(self, port=9472, backends=(9470,9471)):
        self.backends=backends
        self.closed=threading.Event()
        self.mutex=threading.Lock()
        self.condition=threading.Condition(self.mutex)
        self.delay=False
        self.buffered=threading.Event()
        self.buffered_bytes=0
        self.next_backend=0
        self.connections=set()
        self.listener=socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.listener.bind(('0.0.0.0',port));self.listener.listen(32)
        self.listener.settimeout(.2)
        threading.Thread(target=self.accept,daemon=True).start()
    def accept(self):
        while not self.closed.is_set():
            try:front,_=self.listener.accept()
            except (TimeoutError,OSError):continue
            threading.Thread(target=self.connection,args=(front,),daemon=True).start()
    def connection(self,front):
        with self.mutex:
            start=self.next_backend;self.next_backend=(start+1)%len(self.backends)
        back=None
        for offset in range(len(self.backends)):
            try:
                back=socket.create_connection(('127.0.0.1',self.backends[(start+offset)%len(self.backends)]),timeout=1)
                back.settimeout(None);break
            except OSError:pass
        if back is None:front.close();return
        with self.mutex:self.connections.update((front,back))
        def copy(source,target,hold):
            try:
                while not self.closed.is_set():
                    data=source.recv(65536)
                    if not data:break
                    if hold:
                        with self.condition:
                            if self.delay:
                                self.buffered_bytes+=len(data);self.buffered.set()
                                # Keep one opaque chunk per flow in memory; do
                                # not read/decode an unbounded encrypted stream.
                                self.condition.wait_for(lambda:not self.delay or self.closed.is_set())
                    target.sendall(data)
            except OSError:pass
            finally:
                for peer in (source,target):
                    try:peer.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
                    peer.close()
                with self.mutex:self.connections.discard(source);self.connections.discard(target)
        threading.Thread(target=copy,args=(front,back,False),daemon=True).start()
        copy(back,front,True)
    def hold(self):
        with self.condition:
            self.buffered.clear();self.buffered_bytes=0;self.delay=True
    def release(self):
        with self.condition:self.delay=False;self.condition.notify_all()
    def close(self):
        self.closed.set();self.release();self.listener.close()
        with self.mutex:connections=list(self.connections)
        for peer in connections:
            try:peer.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            peer.close()
