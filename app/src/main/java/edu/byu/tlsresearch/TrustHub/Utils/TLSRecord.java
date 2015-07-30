package edu.byu.tlsresearch.TrustHub.Utils;

import java.nio.ByteBuffer;

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

    public static byte getContentType(ByteBuffer packet)
    {
        return packet.get();
    }

    public static short getMajorVersion(ByteBuffer packet)
    {
        return packet.get();
    }

    public static short getMinorVersion(ByteBuffer packet)
    {
        return packet.get();
    }

    public static int getRecordLength(ByteBuffer packet)
    {
        return (int) (((packet.get() & 0xFF) << 8) | (packet.get() & 0xFF)) & 0xFFFF;
    }

}
