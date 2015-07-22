package edu.byu.tlsresearch.TrustHub.Controllers.IPLayer;

import android.util.Log;

import edu.byu.tlsresearch.TrustHub.Controllers.FromApp.VPNServiceHandler;
import edu.byu.tlsresearch.TrustHub.Controllers.TransportLayer.TCPController;
import edu.byu.tlsresearch.TrustHub.Controllers.TransportLayer.UDPController;
import edu.byu.tlsresearch.TrustHub.Utils.IPHeader;
import edu.byu.tlsresearch.TrustHub.Utils.TCPHeader;
import edu.byu.tlsresearch.TrustHub.Utils.UDPHeader;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 1/15/15.
 *
 * Used to strip and reconstruct IPHeaders.
 * Marshalls traffic between VPNServiceHandler and TCP/UDP Controllers
 */
public class IPController
{
    public static void send(byte[] packet)
    {
        byte[] transport = IPHeader.getPayload(packet);
        switch (IPHeader.getProtocol(packet))
        {
            case 17: // UDP
                UDPController.send(new Connection(IPHeader.getDestinationIP(packet),
                        UDPHeader.getDestinationPort(transport), IPHeader.getSourceIP(packet),
                        UDPHeader.getSourcePort(transport)), transport);
                break;
            case 6: // TCP
                TCPController.send(new Connection(IPHeader.getDestinationIP(packet),
                        TCPHeader.getDestinationPort(transport), IPHeader.getSourceIP(packet),
                        TCPHeader.getSourcePort(transport)), transport);
                break;
            default:
                Log.d("IPController", "Protocol not supported: " + IPHeader.getProtocol(packet));
        }
    }

    public static void receive(Connection connection, byte[] packet, byte protocol)
    {
        String[] from = connection.getDestIP().split("[.]");
        String[] to = connection.getClientIP().split("[.]");
        byte[] IPPacket = new byte[IPHeader.IP_HEADER_LENGTH + packet.length];
        int Ipv4 = 4;
        IPPacket[0] = (byte) ((Ipv4 << 4) | (IPHeader.IP_HEADER_LENGTH / IPHeader
                .NUM_BYTES_IN_WORD));
        IPPacket[1] = 0; // Ignore DSCP
        IPPacket[2] = (byte) ((IPPacket.length >> 8) & 0xFF);
        IPPacket[3] = (byte) (IPPacket.length & 0xFF);
        //Log.d("IPController", "Length: " + IPPacket.length);

        // Should be able to be zero because we mark the don't fragment
        IPPacket[4] = 0; // ID
        IPPacket[5] = 0; // ID
        IPPacket[6] = 0x40; // DF Flag and 0 Fragment OFfest
        IPPacket[7] = 0; // 0 Fragment Offset

        IPPacket[8] = 64; // give it a ttl so it's not discarded
        IPPacket[9] = protocol; // TCP Protocol
        IPPacket[10] = 0; // Calculated below: Checksum
        IPPacket[11] = 0;

        IPPacket[12] = (byte) Integer.parseInt(from[0]);
        IPPacket[13] = (byte) Integer.parseInt(from[1]);
        IPPacket[14] = (byte) Integer.parseInt(from[2]);
        IPPacket[15] = (byte) Integer.parseInt(from[3]);

        IPPacket[16] = (byte) Integer.parseInt(to[0]);
        IPPacket[17] = (byte) Integer.parseInt(to[1]);
        IPPacket[18] = (byte) Integer.parseInt(to[2]);
        IPPacket[19] = (byte) Integer.parseInt(to[3]);

        byte[] IPChecksum = IPHeader.getChecksum(IPPacket);
        IPPacket[10] = IPChecksum[0];
        IPPacket[11] = IPChecksum[1];

        for(int i = 0; i < packet.length; i++)
        {
            IPPacket[i + IPHeader.IP_HEADER_LENGTH] = packet[i];
        }
        //Log.d("IPController", "packet: " + byteToHex(IPPacket));
        VPNServiceHandler.getVPNServiceHandler().receive(IPPacket);
    }
}
