package edu.byu.tlsresearch.TrustHub.Utils;

import java.util.Arrays;

public final class IPHeader
{
    public final static int NUM_BYTES_IN_WORD = 4;
    public final static int IP_HEADER_LENGTH = 20;
  	private IPHeader()
	{
	}

    public static boolean isIPPacket(byte[] packet)
    {
        return packet.length >= (packet[0] & 0x0F) * 4;
    }

	public static int getVersion(byte[] packet)
	{
		return packet[0] >> 4;
	}

	public static int getHeaderLength(byte[] packet)
	{
		/**
		 * The second field (4 bits) is the Internet Header Length (IHL), which
		 * is the number of 32-bit words in the header. Since an IPv4 header may
		 * contain a variable number of options, this field specifies the size
		 * of the header (this also coincides with the offset to the data). The
		 * minimum value for this field is 5 (RFC 791), which is a length of
		 * 5×32 = 160 bits = 20 bytes. Being a 4-bit value, the maximum length
		 * is 15 words (15×32 bits) or 480 bits = 60 bytes.
		 */
		return (packet[0] & 0x0F);
	}

	public static int getDscp(byte[] packet)
	{
		return packet[1] >> 2;
	}

	public static int getEcn(byte[] packet)
	{
		return packet[1] & 0x03;
	}

	public static int getTotalLength(byte[] packet)
	{
		return (((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF)) & 0xFFFF;
	}

	public static int getIdentification(byte[] packet)
	{
		return (((packet[4] & 0xFF) << 8) | (packet[5] & 0xFF)) & 0xFFFF;
	}

	public static int getFlags(byte[] packet)
	{
		return (packet[6] & 0xE0);
	}

	public static int getFragmentOffset(byte[] packet)
	{
		return ((packet[6] & 0x1F) << 8) | (packet[7] & 0xFF) & 0xFFFF;
	}

	public static int getTtl(byte[] packet)
	{
		return (packet[8] & 0xFF);
	}

	public static int getProtocol(byte[] packet)
	{
		return (packet[9] & 0xFF);
	}

	public static byte[] getHeaderCheckSum(byte[] packet)
	{
		byte[] toReturn = new byte[2];
		toReturn[0] = packet[10];
		toReturn[1] = packet[11];
		return toReturn;
	}
	
	public static byte[] setHeaderCheckSum(byte[] packet, byte[] toSet)
	{
		packet[10] = toSet[0];
		packet[11] = toSet[1];
        return packet;
	}

	public static String getSourceIP(byte[] packet)
	{
		return (packet[12] & 0xFF) + "." + (packet[13] & 0xFF) + "."
				+ (packet[14] & 0xFF) + "." + (packet[15] & 0xFF);
	}

	public static String getDestinationIP(byte[] packet)
	{
		return (packet[16] & 0xFF) + "." + (packet[17] & 0xFF) + "."
				+ (packet[18] & 0xFF) + "." + (packet[19] & 0xFF);
	}

	public static String getOption(byte[] packet)
	{
		String options = "";
		if (getHeaderLength(packet) > 5)
		{
			for (int i = 20; i < getHeaderLength(packet) * 4; i++)
			{
				options += packet[i];
			}
		}
		return options;
	}

    public static byte[] getPayload(byte[] packet)
    {
        return Arrays.copyOfRange(packet, IPHeader.getHeaderLength(packet) *
                        IPHeader.NUM_BYTES_IN_WORD,
                IPHeader.getTotalLength(packet));
    }

    private static long addUsing1sComplement(long a, long b)
    {
        a += b;
        // If previous result was sign-extended with negatives
        if ((a & 0xFFFF0000) > 0)
        {
            // Clear all sign bits (most significant 16 bits)
            // to cancel 2s complement operations and add 1 (1s complement)
            a = a & 0xFFFF;
            a++;
        }
        return a;
    }

    public static byte[] getChecksum(byte[] raw)
    {
        int length = raw.length;
        int i = 0;
        long currentSum = 0;

        while (length > 1)
        {
            // Adjacent 2 bytes are full 16-bit word for checksum
            // Concatenate them by shifting the left byte up and ORing in the
            // right byte
            // Result is right operand of our 1s complement addition
            currentSum = addUsing1sComplement(currentSum, (((raw[i] << 8) & 0xFF00) | ((raw[i +
                    1]) & 0xFF)));
            i += 2;
            length -= 2;
        }

        // Spec says that of number of bytes in packet is odd we implicitly
        // add another byte of zeroes to the end during checksum calculation
        if (length > 0)
        {
            // Shift left byte up in right operand
            // Implicitly OR in zeroes on the right byte in right operand
            currentSum = addUsing1sComplement(currentSum, (raw[i] << 8 & 0xFF00));

        }

        // Conversion to 1's complement and clear all but the least significant
        // 16 bits
        currentSum = ~currentSum;
        currentSum = currentSum & 0xFFFF;

        // Package result into a big-endian byte array
        byte[] checksum = new byte[2];
        checksum[0] = (byte) ((currentSum >> 8) & 0xFF);
        checksum[1] = (byte) (currentSum & 0xFF);
        return checksum;
    }

//	public static String toString(byte[] packet)
//	{
//		String toReturn = "";
//		toReturn += "Version: " + getVersion(packet) + '\n';
//		toReturn += "HeaderLength: " + getHeaderLength(packet) + '\n';
//		toReturn += "DSCP: " + getDscp(packet) + '\n';
//		toReturn += "ECN: " + getEcn(packet) + '\n';
//		toReturn += "TotalLength: " + getTotalLength(packet) + '\n';
//		toReturn += "Identification: " + getIdentification(packet) + '\n';
//		toReturn += "Flags: " + getFlags(packet) + '\n';
//		toReturn += "FragmentOffset: " + getFragmentOffset(packet) + '\n';
//		toReturn += "TTL: " + getTtl(packet) + '\n';
//		toReturn += "Protocol: " + getProtocol(packet) + '\n';
//		toReturn += "HeaderChecksum: " + IPController.byteToHex(getHeaderCheckSum(packet)) + '\n';
//		toReturn += "SourceIP: " + getSourceIP(packet) + '\n';
//		toReturn += "DestinationIP: " + getDestinationIP(packet) + '\n';
//		toReturn += "Option: " + getOption(packet) + '\n';
//		return toReturn;
//	}
}
