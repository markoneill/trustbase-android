package edu.byu.tlsresearch.TrustHub.Utils;

public final class UDPHeader
{
    public final static int UDP_HEADER_LENGTH_BYTES = 8;

    private UDPHeader(byte[] packet)
    {
        // raw = Arrays.copyOfRange(packet, 0, 8);
    }

    public static int getSourcePort(byte[] packet)
    {
        return ((packet[0] & 0xFF) << 8) | (packet[1] & 0xFF);
    }

    public static int getDestinationPort(byte[] packet)
    {
        return ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
    }

    public static int getLength(byte[] packet)
    {
        /**
         * A field that specifies the length in bytes of the UDP header and UDP
         * data. The minimum length is 8 bytes since that's the length of the
         * header. The field size sets a theoretical limit of 65,535 bytes (8 byte
         * header + 65,527 bytes of data) for a UDP datagram. The practical limit
         * for the data length which is imposed by the underlying IPv4 protocol is
         * 65,507 bytes (65,535 − 8 byte UDP header − 20 byte IP header).[2] In IPv6
         * Jumbograms it is possible to have UDP packets of size greater than 65,535
         * bytes.[5] RFC 2675 specifies that the length field is set to zero if the
         * length of the UDP header plus UDP data is greater than
         */
        return ((packet[4] & 0xFF) << 8) | (packet[5] & 0xFF);
    }

    public static int getChecksum(byte[] packet)
    {
        return ((packet[6] & 0xFF) << 8) | (packet[7] & 0xFF);
    }
}
