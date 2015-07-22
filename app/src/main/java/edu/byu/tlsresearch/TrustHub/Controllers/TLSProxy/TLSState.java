package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import android.util.Log;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import edu.byu.tlsresearch.TrustHub.Utils.TLSHandshake;
import edu.byu.tlsresearch.TrustHub.Utils.TLSRecord;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 5/22/15.
 */
public class TLSState implements TCPInterface
{
    private Map<Connection, connection_state> mStates = new HashMap<>();

    public class connection_state
    {
        public buf_state sendBuffer;
        public buf_state recvBuffer;
        public String hostname;
        public mitm_state MitM;

        public connection_state(Connection context)
        {
            sendBuffer = new buf_state();
            recvBuffer = new buf_state();
            hostname = context.getDestIP();
            MitM = mitm_state.UNKNOWN;
        }
    }

    public enum mitm_state
    {
        PROXY,
        NOPROXY,
        CHECKCERT,
        UNKNOWN
    }

    private enum tls_state
    {
        UNKNOWN,
        HANDSHAKE_LAYER,
        RECORD_LAYER,
        CLIENT_HELLO_SENT,
        SERVER_HELLO_DONE_SENT,
        IRRELEVANT
    }
    private class buf_state
    {
        public byte[] buffer;
        public tls_state curState;
        public int toRead;
        public int readIndex;
        public buf_state()
        {
            buffer = new byte[0];
            curState = tls_state.UNKNOWN;
            toRead = 1;
            readIndex = 0;
        }

    }

    public connection_state getState(Connection context)
    {
        if(!mStates.containsKey(context))
        {
            mStates.put(context, new connection_state(context));
        }
        return mStates.get(context);
    }

    @Override
    public byte[] sending(byte[] packet, Connection context)
    {
        buf_state curCon = null;
        try
        {
            connection_state conState = getState(context);
            curCon = conState.sendBuffer;
            if(curCon.curState != tls_state.IRRELEVANT)
            {
                byte[] temp = new byte[curCon.buffer.length + packet.length];
                System.arraycopy(curCon.buffer, 0, temp, 0, curCon.buffer.length);
                System.arraycopy(packet, 0, temp, curCon.buffer.length, packet.length);
                curCon.buffer = temp;

                while (canTransition(curCon))
                {
                    switch (curCon.curState)
                    {
                        case UNKNOWN:
                            //Log.d("VPN", "S Unknown");
                            handle_state_unknown(packet, curCon);
                            break;
                        case RECORD_LAYER:
                            //Log.d("VPN", "S Record Layer");
                            handle_state_record_layer(packet, curCon);
                            break;
                        case HANDSHAKE_LAYER:
                            //Log.d("VPN", "S Handshake Layer");
                            handle_state_handshake_layer(packet, curCon, conState);
                            break;
                        case CLIENT_HELLO_SENT:
                            //Log.d("VPN", "S Client Hello Sent");
                            handle_state_server_hello_done_sent(packet, curCon);
                            break;
                        case IRRELEVANT:
                            //Log.d("VPN", "S IRRELEVANT");
                            curCon.toRead = 0;
                            break;
                    }
                }
                curCon.buffer = new byte[0];
            }
        }
        catch(Exception e)
        {
            if(curCon != null)
            {
                curCon.curState = tls_state.IRRELEVANT;
                curCon.toRead = 0;
            }
            Log.d("VPN", "WHAT THE CRAP: " + e.getMessage() + "\n" + e.toString());
        }

        return packet;
    }

    @Override
    public byte[] received(byte[] packet, Connection context)
    {
        buf_state curCon = null;
        try
        {
            connection_state conState = getState(context);
            curCon = conState.recvBuffer;
            if(curCon.curState != tls_state.IRRELEVANT)
            {
                byte[] temp = new byte[curCon.buffer.length + packet.length];
                System.arraycopy(curCon.buffer, 0, temp, 0, curCon.buffer.length);
                System.arraycopy(packet, 0, temp, curCon.buffer.length, packet.length);
                curCon.buffer = temp;

                while (canTransition(curCon))
                {
                    switch (curCon.curState)
                    {
                        case UNKNOWN:
                            //Log.d("VPN", "Unknown");
                            handle_state_unknown(packet, curCon);
                            break;
                        case RECORD_LAYER:
                            //Log.d("VPN", "Record Layer");
                            handle_state_record_layer(packet, curCon);
                            break;
                        case HANDSHAKE_LAYER:
                            //Log.d("VPN", "Handshake Layer");
                            handle_state_handshake_layer(packet, curCon, conState);
                            break;
                        case SERVER_HELLO_DONE_SENT:
                            //Log.d("VPN", "Server Certificates Sent");
                            handle_state_server_hello_done_sent(packet, curCon);
                            break;
                        case IRRELEVANT:
                            //Log.d("VPN", "IRRELEVANT");
                            curCon.toRead = 0;
                            break;
                    }
                }
                curCon.buffer = new byte[0];
            }
        }
        catch(Exception e)
        {
            if(curCon != null)
            {
                curCon.curState = tls_state.IRRELEVANT;
                curCon.toRead = 0;
            }
            Log.d("VPN", "WHAT THE CRAP: " + e.getMessage() + "\n" + e.toString());
        }

        return packet;
    }

    private boolean canTransition(buf_state state)
    {
        return state.toRead > 0 && state.buffer.length >= state.toRead;
    }

    private void handle_state_unknown(byte[] packet, buf_state context)
    {
        if(TLSRecord.getContentType(packet, context.readIndex) == TLSRecord.HANDSHAKE)
        {
            context.curState = tls_state.RECORD_LAYER;
            context.toRead = TLSRecord.RECORD_HEADER_SIZE;
        }
        else
        {
            context.curState = tls_state.IRRELEVANT;
            context.toRead = 0;
        }
    }

    private void handle_state_record_layer(byte[] packet, buf_state context)
    {
        short tls_major_version = TLSRecord.getMajorVersion(packet, context.readIndex);
        short tls_minor_version = TLSRecord.getMinorVersion(packet, context.readIndex);
        int tls_record_length = TLSRecord.getRecordLength(packet, context.readIndex);

        //Log.d("VPN", "Major: " + packet[1+ context.readIndex] + " Minor: " + packet[2 + context.readIndex] + " RecordLength: " + packet[3 + context.readIndex] + " " + packet[4 + context.readIndex]);
        //Log.d("VPN", "Major: " + tls_major_version + " Minor: " + tls_minor_version + " RecordLength: " + tls_record_length);

        if(TLSRecord.getContentType(packet, context.readIndex) == TLSRecord.HANDSHAKE)
        {
            context.curState = tls_state.HANDSHAKE_LAYER;
            context.readIndex += context.toRead;
            context.toRead = tls_record_length;
        }
        else
        {
            context.curState = tls_state.IRRELEVANT;
            context.toRead = 0;
        }
    }

    private void handle_state_handshake_layer(byte[] packet, buf_state context, connection_state con)
    {
        int tls_record_bytes = context.toRead;
        //Log.d("VPN", "RecordLength: " + tls_record_bytes);
        int handshake_length;
        while(tls_record_bytes > 0)
        {
            handshake_length = TLSHandshake.getHandshakeDataLength(packet, context.readIndex) + TLSHandshake.HANDSHAKE_HEADER_SIZE;
            //Log.d("VPN", "MessageLength: " + handshake_length);
            tls_record_bytes -= handshake_length;
            int type = TLSHandshake.getHandshakeMessageType(packet, context.readIndex);
            //Log.d("VPN", "Type: " + type);
            switch(type)
            {
                case TLSHandshake.TYPE_CLIENT_HELLO:
                    context.toRead = 0;
                    context.curState = tls_state.CLIENT_HELLO_SENT;
                    String hostname = getHostname(packet, context);
                    if(hostname != null)
                        con.hostname = getHostname(packet, context);
                    context.readIndex += handshake_length;
                    break;
                case TLSHandshake.TYPE_SERVER_HELLO:
                    //Log.d("VPN", "Server Hello");
                    context.toRead = TLSRecord.RECORD_HEADER_SIZE;
                    context.curState = tls_state.RECORD_LAYER;
                    context.readIndex += handshake_length;
                    break;
                case TLSHandshake.TYPE_CERTIFICATE:
                    //Log.d("VPN", "Certificate");
                    handle_certificate(packet, context, con);
                    context.toRead = TLSRecord.RECORD_HEADER_SIZE;
                    context.curState = tls_state.RECORD_LAYER;
                    context.readIndex += handshake_length;
                    break;
                case TLSHandshake.TYPE_SERVER_KEY_EXCHANGE:
                    //Log.d("VPN", "TYPE_SERVER_KEY_EXCHANGE");
                    context.toRead = TLSRecord.RECORD_HEADER_SIZE;
                    context.curState = tls_state.RECORD_LAYER;
                    context.readIndex += handshake_length;
                case TLSHandshake.TYPE_SERVER_HELLO_DONE:
                    //Log.d("VPN", "TYPE_SERVER_HELLO_DONE");
                    context.toRead = 0;
                    context.curState = tls_state.SERVER_HELLO_DONE_SENT;
                    context.readIndex += handshake_length;
                    break;
                default:
                    context.toRead = 0;
                    context.curState = tls_state.IRRELEVANT;
                    context.readIndex += handshake_length;
                    tls_record_bytes = 0;
                    break;
            }
        }
    }


    private void handle_certificate(byte[] packet, buf_state context, connection_state con)
    {
        int handshake_message_length = TLSHandshake.getHandshakeDataLength(packet, context.readIndex);
        final List<X509Certificate> certs = TLSHandshake.getCertificates(packet, context.readIndex);
        Log.d("TLSState", "Got Certificate for: " + con.hostname);

        boolean trusted = false;
        try
        {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore)null);
            for(TrustManager tm: trustManagerFactory.getTrustManagers())
            {
                if(tm instanceof X509TrustManager)
                {
                    try
                    {
                        X509Certificate[] chain = new X509Certificate[certs.size()];
                        certs.toArray(chain);
                        ((X509TrustManager)tm).checkServerTrusted(chain, "RSA");
                        trusted = true;
                    } catch (CertificateException e)
                    {
                        Log.d("TLSState", e.getMessage());
                        //Not trusted
                    }
                }
            }

        } catch (NoSuchAlgorithmException e)
        {

        } catch (KeyStoreException e)
        {

        }

        Log.d("TLSState", "Trusted: " + trusted);

        if(trusted)
            con.MitM = mitm_state.NOPROXY;
        else
            con.MitM = mitm_state.CHECKCERT;
    }

    private String getHostname(byte[] packet, buf_state context)
    {
        int hello_length = TLSHandshake.getHandshakeDataLength(packet, context.readIndex);
        return TLSHandshake.getClientHelloServerName(packet, context.readIndex);
    }

    private void handle_state_client_hello_sent(byte[] packet, buf_state context)
    {
        context.toRead = 0;
        context.curState = tls_state.IRRELEVANT;
    }

    private void handle_state_server_hello_done_sent(byte[] packet, buf_state context)
    {
        context.toRead = 0;
        context.curState = tls_state.IRRELEVANT;
    }
}
