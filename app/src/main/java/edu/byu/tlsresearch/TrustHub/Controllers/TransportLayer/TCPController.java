package edu.byu.tlsresearch.TrustHub.Controllers.TransportLayer;

import android.util.Log;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

import edu.byu.tlsresearch.TrustHub.Controllers.Channel.TCPChannel;
import edu.byu.tlsresearch.TrustHub.Controllers.IPLayer.IPController;
import edu.byu.tlsresearch.TrustHub.Utils.IPHeader;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 1/15/15.
 * <p/>
 * Handles all TCP Sockets.
 * Marshalls traffic between IPController and TCPChannel.
 * Strips and reconstructs TCPHeaders
 */
public final class TCPController
{
    private final static int PSUEDO_HEADER_LENGTH = 12;
    private final static Map<Connection, TCPChannel> clients = new ConcurrentHashMap<Connection,
            TCPChannel>();
    private final static ReentrantLock clientsLock = new ReentrantLock();

    public static void send(Connection context, byte[] transport)
    {
        try
        {
            TCPChannel connectionChannel = clients.get(context);
            if (connectionChannel == null)
            {
                connectionChannel = new TCPChannel(context, transport);
                clientsLock.lock();
                clients.put(context, connectionChannel);
                //Log.d("TCPController", "1 clients unLock");
                clientsLock.unlock();
            }
            connectionChannel.send(transport);
        } catch (IOException e)
        {
            Log.e("TCPController", "failed to connect" + e.getMessage());
        }
    }

    public static void remove(Connection toRemove)
    {
        //Log.d("TCPController", "1 clients Lock: " + clientsLock.isHeldByCurrentThread());
        clientsLock.lock();
        clients.remove(toRemove);
        //Log.d("TCPController", "1 clients unLock");
        clientsLock.unlock();
    }

    public static void receive(byte[] payload, TCPChannel context, int flags)
    {
        byte[] TCPPacket = new byte[20 + payload.length];
        Connection connection = context.getmContext();
        // TCP HEADER
        TCPPacket[0] = (byte) (connection.getDestPort() >> 8);
        TCPPacket[1] = (byte) ((connection.getDestPort() & 0xFF));
        TCPPacket[2] = (byte) (connection.getClientPort() >> 8);
        TCPPacket[3] = (byte) ((connection.getClientPort() & 0xFF));

        TCPPacket[4] = (byte) ((context.getSEQ() >> 24) & 0xFF);
        TCPPacket[5] = (byte) ((context.getSEQ() >> 16) & 0xFF);
        TCPPacket[6] = (byte) ((context.getSEQ() >> 8) & 0xFF);
        TCPPacket[7] = (byte) (context.getSEQ() & 0xFF);

        TCPPacket[8] = (byte) ((context.getACK() >> 24) & 0xFF);
        TCPPacket[9] = (byte) ((context.getACK() >> 16) & 0xFF);
        TCPPacket[10] = (byte) ((context.getACK() >> 8) & 0xFF);
        TCPPacket[11] = (byte) ((context.getACK()) & 0xFF);

        TCPPacket[12] = (byte) 5 << 4;
        TCPPacket[13] = (byte) flags;
        // I think 65535 is a standard window size
        TCPPacket[14] = (byte) ((65535 >> 8) & 0xFF);
        TCPPacket[15] = (byte) (65535 & 0xFF);

        TCPPacket[16] = 0; // Calculated below
        TCPPacket[17] = 0;

        // No urgent pointer
        TCPPacket[18] = 0;
        TCPPacket[19] = 0;

        System.arraycopy(payload, 0, TCPPacket, 20, payload.length);

        byte[] psuedoHeader = new byte[TCPPacket.length + PSUEDO_HEADER_LENGTH];

//        InetAddress local = ((SocketChannel)context.getmChannelKey().channel()).socket()
//                .getLocalAddress();
//        InetAddress dest = ((SocketChannel)context.getmChannelKey().channel()).socket()
//                .getInetAddress();
        String[] destAddress = connection.getDestIP().split("[.]");
        String[] localAddress = connection.getClientIP().split("[.]");

//        byte[] destAddress = dest.getAddress();
//        byte[] localAddress = local.getAddress();


        psuedoHeader[0] = (byte) Integer.parseInt(destAddress[0]);
        psuedoHeader[1] = (byte) Integer.parseInt(destAddress[1]);
        psuedoHeader[2] = (byte) Integer.parseInt(destAddress[2]);
        psuedoHeader[3] = (byte) Integer.parseInt(destAddress[3]);

        psuedoHeader[4] = (byte) Integer.parseInt(localAddress[0]);
        psuedoHeader[5] = (byte) Integer.parseInt(localAddress[1]);
        psuedoHeader[6] = (byte) Integer.parseInt(localAddress[2]);
        psuedoHeader[7] = (byte) Integer.parseInt(localAddress[3]);

        psuedoHeader[8] = 0x00;
        psuedoHeader[9] = 0x06;

        psuedoHeader[10] = (byte) ((TCPPacket.length >> 8) & 0xFF);
        psuedoHeader[11] = (byte) (TCPPacket.length & 0xFF);

        System.arraycopy(TCPPacket, 0, psuedoHeader, 12, TCPPacket.length);

        byte[] checksum = IPHeader.getChecksum(psuedoHeader);
        TCPPacket[16] = checksum[0];
        TCPPacket[17] = checksum[1];

        IPController.receive(connection, TCPPacket, (byte) 0x06);
    }
}
