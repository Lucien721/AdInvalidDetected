package com.ibm.zrl.idmx.tests.idmx;
import org.zeromq.ZMQ;
import org.zeromq.ZMQ.Context;
import org.zeromq.ZMQ.Socket;
import java.util.Date;
public class SCAudit {
    public static void main(String[] args) throws Exception{
        ZMQ.Context context = ZMQ.context(1);
        ZMQ.Socket socket = context.socket(ZMQ.REP);
        socket.bind ("tcp://127.0.0.1:9005");

        while (true) {
            byte[] recv = socket.recv(0);
            String recvStr = new String(recv);
            System.out.println("recv:" + recvStr);
            String time = new Date().getTime() + "";

            byte[] reply = time.getBytes();
            socket.send(reply, 0);
        }
    }
}
