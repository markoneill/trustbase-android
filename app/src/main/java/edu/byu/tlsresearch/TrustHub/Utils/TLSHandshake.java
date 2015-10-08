package edu.byu.tlsresearch.TrustHub.Utils;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 * Created by sheidbri on 5/14/15.
 */
public class TLSHandshake
{
    public final static byte TYPE_HELLO_REQUEST = 0;
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
    private static final int CERT_HEADER_LENGTH = 3;

    /* Indexed from Handshake Content */
    public static byte getHandshakeMessageType(ByteBuffer buffer)
    {
        return buffer.get();
    }

    public static int getHandshakeDataLength(ByteBuffer buffer)
    {
        return (((buffer.get() & 0xFF) << 16) | ((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF)) & 0xFFFFFF;
    }

    public static byte getClientHelloMajorVersion(ByteBuffer buffer)
    {
        return buffer.get();
    }

    public static byte getClientHelloMinorVersion(ByteBuffer buffer)
    {
        return buffer.get();
    }

    public static byte[] getClientHelloRandom(ByteBuffer buffer)
    {
        byte[] toReturn = new byte[32];
        buffer.get(toReturn);
        return toReturn;
    }

    public static short getClientHelloSessionIdLength(ByteBuffer buffer)
    {
        return (short) (buffer.get() & 0xFF);
    }

    public static byte[] getClientHelloSessionID(ByteBuffer buffer, short idLength)
    {
        byte[] toReturn = new byte[idLength];
        buffer.get(toReturn);
        return toReturn;
    }

    public static int getCipherSuiteLength(ByteBuffer buffer)
    {
        return (((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF)) & 0xFFFF;
    }

    public static byte[] getCipherSuites(ByteBuffer buffer, int cipher_length)
    {
        byte[] toReturn = new byte[cipher_length];
        buffer.get(toReturn);
        return toReturn;
    }

    public static short getClientHelloCompressionMethodsLength(ByteBuffer buffer)
    {
        return (short) (buffer.get() & 0xFF);
    }

    public static byte[] getClientHelloCompressionMethods(ByteBuffer buffer, short compression_length)
    {
        byte[] toReturn = new byte[compression_length];
        buffer.get(toReturn);
        return toReturn;
    }

    public static int getClientHelloExtensionsLength(ByteBuffer buffer)
    {
        return (((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF)) & 0xFFFF;
    }

    public static int getExtensionType(ByteBuffer buffer)
    {
        return (((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF)) & 0xFFFF;
    }

    public static int getExtensionLength(ByteBuffer buffer)
    {
        return (((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF)) & 0xFFFF;
    }


    public static String getClientHelloServerName(ByteBuffer buffer)
    {
        String hostname;
        int NameListLength = (((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF)) & 0xFFFF;
        short NameType = (short) (buffer.get() & 0xFF);
        int NameLength = (((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF)) & 0xFFFF;
        byte[] hostname_bytes = new byte[NameLength];
        buffer.get(hostname_bytes);
        hostname = new String(hostname_bytes);
        return hostname;
    }

    public static ArrayList<X509Certificate> getCertificates(ByteBuffer buffer)
    {
        try
        {
            int certsLength = (((buffer.get() & 0xFF) << 16) | ((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF)) & 0xFFFFFF;
            int certLength = 0;
            ArrayList<X509Certificate> toReturn = new ArrayList<X509Certificate>();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            for (int i = 0; i < certsLength; i += certLength + TLSHandshake.CERT_HEADER_LENGTH)
            {
                certLength = (((buffer.get() & 0xFF) << 16) | ((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF)) & 0xFFFFFF;
                byte[] cert_bytes = new byte[certLength];
                buffer.get(cert_bytes);
                InputStream in = new ByteArrayInputStream(cert_bytes);
                X509Certificate toAdd = (X509Certificate) certFactory.generateCertificate(in);
                toReturn.add(toAdd);
            }
            return toReturn;
        }
        catch (CertificateException e)
        {
            Log.e("TLSRecord", "Creating certificate generator failed");
            return null;
        }
        catch (Exception e)
        {
            Log.e("TLSRecord", "Java sucks " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}
