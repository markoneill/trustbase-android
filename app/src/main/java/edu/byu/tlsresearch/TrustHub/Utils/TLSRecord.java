package edu.byu.tlsresearch.TrustHub.Utils;

/**
 * Created by sheidbri on 5/6/15.
 */
public class TLSRecord
{
    public final static byte CHANGE_CIPHER_SPEC = 0x14;
    public final static byte ALERT = 0x15;
    public final static byte HANDSHAKE = 0x16;
    public final static byte HEARTBEAT = 0x18;

    public final static byte RECORD_HEADER_SIZE = 5;

    public static byte getContentType(byte[] packet, int offset)
    {
        return packet[offset];
    }

    public static short getMajorVersion(byte[] packet, int offset)
    {
        return packet[1 + offset];
    }

    public static short getMinorVersion(byte[] packet, int offset)
    {
        return packet[2 + offset];
    }

    public static int getRecordLength(byte[] packet, int offset)
    {
        return (int) (((packet[3 + offset] & 0xFF) << 8) | (packet[4 + offset] & 0xFF)) & 0xFFFF;
    }

}
