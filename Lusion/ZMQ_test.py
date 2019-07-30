10import zmq
import time

context = zmq.Context()
sock = context.socket(zmq.REQ)
sock.connect('tcp://127.0.0.1:9005')
while True:
    sock.send_string("")
    print(sock.recv())
    time.sleep(1)