package edu.byu.tlsresearch.TrustHub.Controllers.TransportLayer;

import android.util.Log;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import edu.byu.tlsresearch.TrustHub.Controllers.Channel.UDPChannel;
import edu.byu.tlsresearch.TrustHub.Controllers.IPLayer.IPController;
import edu.byu.tlsresearch.TrustHub.Controllers.Socket.SocketPoller;
import edu.byu.tlsresearch.TrustHub.Utils.UDPHeader;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 1/15/15.
 *
 * Manages all UDP connections.
 * Marshalls traffic between IPController and UDPChannel.
 * Handles stripping and Reconstructing the Headers
 */
public final class UDPController
{
    private static Map<Integer, UDPChannel> clients = new ConcurrentHashMap<Integer,
                UDPChannel>();
    public static void send(Connection context, byte[] packet)
    {
        UDPChannel connectionState = clients.get(context.getClientPort());
        if(connectionState == null)
        {
            connectionState = new UDPChannel(context, packet);
            clients.put(context.getClientPort(), connectionState);
        }
        connectionState.send(context, packet);
    }

    public static byte[] stripHeaders(byte[] packet)
    {
        return Arrays.copyOfRange(packet, UDPHeader.UDP_HEADER_LENGTH_BYTES,
                UDPHeader.getLength(packet));
    }

    public static void receive(byte[] payload, UDPChannel context)
    {
        byte[] UDPPacket = new byte[UDPHeader.UDP_HEADER_LENGTH_BYTES + payload.length];
        int localPort = context.getmContext().getClientPort();
        int destPort = context.getmContext().getDestPort();

        UDPPacket[0] = (byte) (destPort >> 8);
        UDPPacket[1] = (byte) (destPort & 0xFF);
        UDPPacket[2] = (byte) (localPort >> 8);
        UDPPacket[3] = (byte) (localPort & 0xFF);
        UDPPacket[4] = (byte) (UDPPacket.length >> 8);
        UDPPacket[5] = (byte) (UDPPacket.length & 0xFF);
        // Checksum is optional....Hopefully
        UDPPacket[6] = 0;
        UDPPacket[7] = 0;
        for(int i = 0; i < payload.length; i++)
        {
            UDPPacket[i + UDPHeader.UDP_HEADER_LENGTH_BYTES] = payload[i];
        }
        IPController.receive(context.getmContext(), UDPPacket, (byte) 0x11);
    }

    public static void remove(Connection toRemove)
    {
        clients.remove(toRemove);
    }

    public static void markAndSweep()
    {
        try
        {
            Iterator it = clients.entrySet().iterator();
            while (it.hasNext())
            {
                Map.Entry pair = (Map.Entry) it.next();
                if (System.currentTimeMillis() - ((UDPChannel) pair.getValue()).isRecentlyUsed() > 5000)
                {
                    //clients.remove(pair.getKey());
                    //Log.d("UDPChannel", "size of clients before it.remove()" + clients.size());
                    SocketPoller.getInstance().close(((UDPChannel) pair.getValue()).getmChannelKey());
                    it.remove();
                    //Log.d("UDPChannel", "size of clients after it.remove()" + clients.size());
                    //Log.d("UDPChannel", "removed");
                }
            }
        }
        catch (Exception e) {
            Log.d("UDPChannel", "mark and sweep died "  + e.getMessage());
        }

    }
}
