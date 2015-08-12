package edu.byu.tlsresearch.TrustHub.Utils;

import java.util.Arrays;

public final class TCPHeader
{
    public final static short FIN = 0x01;
    public final static short SYN = 0x02;
    public final static short RST = 0x04;
    public final static short PSH = 0x08;
    public final static short ACK = 0x10;
    public final static short URG = 0x20;
    public final static short ECE = 0x40;
    public final static short CWR = 0x80;
    public final static short NS = 0x100;

	public static int getSourcePort(byte[] packet)
	{
		return ((packet[0] & 0xFF) << 8) | (packet[1] & 0xFF);
	}

	public static int getDestinationPort(byte[] packet)
	{
		return ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
	}

	public static long getSequenceNumber(byte[] packet)
	{
		return (long) (((packet[4] & 0xFF) << 24) | ((packet[5] & 0xFF) << 16)
				| ((packet[6] & 0xFF) << 8) | (packet[7] & 0xFF));
	}

	public static long getAckNumber(byte[] packet)
	{
		return (long) (((packet[8] & 0xFF) << 24) | ((packet[9] & 0xFF) << 16)
				| ((packet[10] & 0xFF) << 8) | (packet[11] & 0xFF));
	}

	public static int getDataOffset(byte[] packet)
	{
		/**
		 * specifies the size of the TCP header in 32-bit words. The minimum
		 * size header is 5 words and the maximum is 15 words thus giving the
		 * minimum size of 20 bytes and maximum of 60 bytes, allowing for up to
		 * 40 bytes of options in the header. This field gets its name from the
		 * fact that it is also the offset from the start of the TCP segment to
		 * the actual data.
		 */

		return (packet[12] & 0xF0) >> 4;
	}

	public static int getReserved(byte[] packet)
	{
		return (packet[12] & 0x0E);
	}

	public static int getFlags(byte[] packet)
	{
		return (packet[12] & 0x01) << 8 | (packet[13] & 0xFF);
	}

	public static int getWindowSize(byte[] packet)
	{
		return ((packet[14] & 0xFF) << 8) | (packet[15] & 0xFF);
	}

	public static int getCheckSum(byte[] packet)
	{
		return ((packet[16] & 0xFF) << 8) | (packet[17] & 0xFF);
	}

	public static int getUrgentPointer(byte[] packet)
	{
		return ((packet[18] & 0xFF) << 8) | (packet[19] & 0xFF);
	}

	public static String getOption(byte[] packet)
	{
		String option = "";
		if (getDataOffset(packet) > 5)
		{
			for (int i = 20; i < getDataOffset(packet) * 4; i++)
			{
				option += packet[i];
			}
		}
		return option;
	}

    public static byte[] getPayload(byte[] transport)
    {
        return Arrays.copyOfRange(transport, TCPHeader.getDataOffset(transport) * IPHeader.NUM_BYTES_IN_WORD,
                transport.length);
    }

	public static String toString(byte[] packet)
	{
		String toReturn = "";
		toReturn += "SourcePort: " + getSourcePort(packet) + '\n';
		toReturn += "DestinationPort: " + getDestinationPort(packet) + '\n';
		toReturn += "SequenceNumber: " + getSequenceNumber(packet) + '\n';
		toReturn += "AckNumber: " + getAckNumber(packet) + '\n';
		toReturn += "DataOffset: " + getDataOffset(packet) + '\n';
		toReturn += "Reserved: " + getReserved(packet) + '\n';
		toReturn += "Flags: " + getFlags(packet) + '\n';
		toReturn += "WindowSize: " + getWindowSize(packet) + '\n';
		toReturn += "CheckSum: " + getCheckSum(packet) + '\n';
		toReturn += "UrgentPointer: " + getUrgentPointer(packet) + '\n';
		toReturn += "Options: " + getOption(packet) + '\n';
		return toReturn;
	}
}
