package edu.byu.tlsresearch.TrustHub.Utils;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Created by sheidbri on 5/14/15.
 */
public class TLSHandshake
{
    public final static byte TYPE_HELLO_REQUEST	= 0;
    public final static byte TYPE_CLIENT_HELLO = 1;
    public final static byte TYPE_SERVER_HELLO = 2;
    public final static byte TYPE_CERTIFICATE = 11;
    public final static byte TYPE_SERVER_KEY_EXCHANGE = 12;
    public final static byte TYPE_CERTIFICATE_REQUEST = 13;
    public final static byte TYPE_SERVER_HELLO_DONE = 14;
    public final static byte TYPE_CERTIFICATE_VERIFY = 15;
    public final static byte TYPE_CLIENT_KEY_EXCHANGE = 16;
    public final static byte TYPE_FINISHED = 20;
    public final static short EXTENSION_TYPE_SERVER_NAME = 0x0000;

    public final static byte HANDSHAKE_HEADER_SIZE = 4;

    /* Indexed from Handshake Content */
    public static int getHandshakeMessageType(byte[] packet, int offset)
    {
        return (int) packet[offset];
    }

    public static int getHandshakeDataLength(byte[] packet, int offset)
    {
        return (int) (((packet[offset + 1] & 0xFF) << 16) | ((packet[offset + 2] & 0xFF) << 8) | (packet[offset + 3] & 0xFF)) & 0xFFFFFF;
    }

    public static int getClientHelloMajorVersion(byte[] packet, int offset)
    {
        return packet[4 + offset];
    }

    public static int getClientHelloMinorVersion(byte[] packet, int offset)
    {
        return packet[5 + offset];
    }

    public static byte[] getClientHelloRandom(byte[] packet, int offset)
    {
        return Arrays.copyOfRange(packet, 6 + offset, 37 + offset);
    }

    public static short getClientHelloSessionIdLength(byte[] packet, int offset)
    {
        return (short) (packet[38 + offset] & 0xFF);
    }

    public static byte[] getClientHelloSessionID(byte[] packet, int offset)
    {
        return Arrays.copyOfRange(packet, 39 + offset, getClientHelloSessionIdLength(packet, offset) + offset);
    }

    public static int getCipherSuiteLength(byte[] packet, int offset)
    {
        return (int) (((packet[39 + getClientHelloSessionIdLength(packet, offset) + offset] & 0xFF) << 8) |
                        (packet[40 + getClientHelloSessionIdLength(packet, offset) + offset] & 0xFF)) & 0xFFFF;
    }

    public static short getClientHelloCompressionMethodsLength(byte[] packet, int offset)
    {
        return (short) (packet[41 + getClientHelloSessionIdLength(packet, offset) +
                                    getCipherSuiteLength(packet, offset) +
                                    offset] & 0xFF);
    }

    public static int getClientHelloExtensionsLength(byte[] packet, int offset)
    {
        return (int) (((packet[42 + getClientHelloSessionIdLength(packet, offset) +
                                 getCipherSuiteLength(packet, offset) +
                                 getClientHelloCompressionMethodsLength(packet, offset) +
                                 offset]
                             & 0xFF) << 8) |
                           (packet[43 + getClientHelloSessionIdLength(packet, offset) +
                                     getCipherSuiteLength(packet, offset) +
                                     getClientHelloCompressionMethodsLength(packet, offset) +
                                     offset]
                                 & 0xFF))
                       & 0xFFFF;
    }

    public static String getClientHelloServerName(byte[] packet, int offset)
    {
        int start = 44 +
                    getClientHelloSessionIdLength(packet, offset) +
                    getCipherSuiteLength(packet, offset) +
                    getClientHelloCompressionMethodsLength(packet, offset) +
                    offset;
        int length = getClientHelloExtensionsLength(packet, offset);
        String hostname = null;
        while(start < length)
        {
            short type = (short) ((((packet[start] & 0xFF) << 8) | (packet[start + 1] & 0xFF)) & 0xFFFF);
            int extlen = (int) ((((packet[start + 2] & 0xFF) << 8) | (packet[start + 3] & 0xFF)) & 0xFFFF);
            if(type == EXTENSION_TYPE_SERVER_NAME)
            {
                int NameListLength = (int) ((((packet[start + 4] & 0xFF) << 8) | (packet[start + 5] & 0xFF)) & 0xFFFF);
                short NameType = (short) (packet[start + 6] & 0xFF);
                int NameLength = (int) ((((packet[start + 7] & 0xFF) << 8) | (packet[start + 8] & 0xFF)) & 0xFFFF);
                //Log.d("Handshake Handler", "Getting hostname: " + start + (start + NameLength));
                hostname = new String(Arrays.copyOfRange(packet, start + 9, start + 9 + NameLength));
                //Log.d("Handshake Handler", "Hostname: " + hostname);
                start = length;
            }
            start += length;
        }
        return hostname;
    }

    public static ArrayList<X509Certificate> getCertificates(byte[] packet, int offset)
    {
        try
        {
            int certsLength = (int) (((packet[4 + offset] & 0xFF) << 16) | ((packet[5 + offset] & 0xFF) << 8) | (packet[6 + offset] & 0xFF)) & 0xFFFFFF;
            int certLength = 0;
            ArrayList<X509Certificate> toReturn = new ArrayList<>();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            for (int i = 7 + offset; i < certsLength + 7 + offset; i += certLength + 3)
            {
                certLength = (int) (((packet[i] & 0xFF) << 16) | ((packet[i + 1] & 0xFF) << 8) | (packet[i + 2] & 0xFF)) & 0xFFFFFF;
                InputStream in = new ByteArrayInputStream(Arrays.copyOfRange(packet, i + 3, certLength + i + 3));
                X509Certificate toAdd = (X509Certificate) certFactory.generateCertificate(in);
                toReturn.add(toAdd);
            }

            return toReturn;
        } catch (CertificateException e)
        {
            Log.e("TLSRecord", "Creating certificate generator failed");
            return null;
        } catch (Exception e)
        {
            Log.e("TLSRecord", "Java sucks " + e.getMessage());
            return null;
        }
    }
}
