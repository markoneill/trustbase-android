package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import android.util.Log;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import edu.byu.tlsresearch.TrustHub.Utils.TLSHandshake;
import edu.byu.tlsresearch.TrustHub.Utils.TLSRecord;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 5/22/15.
 */
public class TLSState implements TCPInterface
{
    private static String TAG = "TLSState";
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
        public ByteBuffer buffer;
        public int toRead;
        public tls_state curState;
        public buf_state()
        {
            buffer = ByteBuffer.allocate(65535);
            curState = tls_state.UNKNOWN;
            toRead = 1;
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
        connection_state conState = getState(context);
        buf_state curCon = conState.sendBuffer;
        try
        {
            if(curCon.curState != tls_state.IRRELEVANT)
            {
                Log.d(TAG, "Send Cur State " + curCon.curState + " " + context.toString());
                Log.d(TAG, "" + curCon.buffer);
                curCon.buffer.put(packet); //TODO: check overflow
                curCon.buffer.flip();
                while (canTransition(curCon))
                {
                    switch (curCon.curState)
                    {
                        case UNKNOWN:
                            Log.d(TAG, "Send Unknown");
                            handle_state_unknown(curCon);
                            break;
                        case RECORD_LAYER:
                            Log.d(TAG, "Send Record");
                            handle_state_record_layer(curCon);
                            break;
                        case HANDSHAKE_LAYER:
                            Log.d(TAG, "Send Handshake");
                            handle_state_handshake_layer(curCon, conState);
                            break;
                        case CLIENT_HELLO_SENT:
                            Log.d(TAG, "Send ClientHelloSent");
                            handle_state_client_hello_sent(curCon);
                            break;
                        case IRRELEVANT:
                            Log.d(TAG, "Send Irrelevant");
                            curCon.buffer.position(curCon.buffer.limit());
                            curCon.toRead = 0;
                            break;
                    }
                }
                curCon.buffer.compact();
            }
        }
        catch(Exception e)
        {
            if(curCon != null)
            {
                //curCon.curState = tls_state.IRRELEVANT;
            }
            Log.d(TAG, "Send WHAT THE CRAP: " + e.getMessage() + "\n" + e.toString());
            e.printStackTrace();
        }

        return packet;
    }

    @Override
    public byte[] received(byte[] packet, Connection context)
    {
        connection_state conState = getState(context);
        buf_state curCon = conState.recvBuffer;
        try
        {
            if(curCon.curState != tls_state.IRRELEVANT)
            {
                Log.d(TAG, "Read Cur State " + curCon.curState + " " + context.toString());
                Log.d(TAG, ""+curCon.buffer);
                curCon.buffer.put(packet);//TODO: check overflow
                curCon.buffer.flip();
                while (canTransition(curCon))
                {
                    switch (curCon.curState)
                    {
                        case UNKNOWN:
                            Log.d(TAG, "Read Unknown");
                            handle_state_unknown(curCon);
                            break;
                        case RECORD_LAYER:
                            Log.d(TAG, "Read Record_layer");
                            handle_state_record_layer(curCon);
                            break;
                        case HANDSHAKE_LAYER:
                            Log.d(TAG, "Read Handshake layer");
                            handle_state_handshake_layer(curCon, conState);
                            break;
                        case SERVER_HELLO_DONE_SENT:
                            Log.d(TAG, "Read Server Hello Done Sent");
                            handle_state_server_hello_done_sent(curCon);
                            break;
                        case IRRELEVANT:
                            Log.d(TAG, "Read Irrelevant");
                            curCon.buffer.position(curCon.buffer.limit());
                            curCon.toRead = 0;
                            break;
                    }
                }
                curCon.buffer.compact();
            }
        }
        catch(Exception e)
        {
            if(curCon != null)
            {
                //curCon.curState = tls_state.IRRELEVANT;
            }
            Log.d(TAG, "Receive WHAT THE CRAP: " + e.getMessage() + "\n" + e.toString());
            e.printStackTrace();
        }

        return packet;
    }

    private boolean canTransition(buf_state state)
    {
        return state.buffer.remaining() >= state.toRead && state.toRead > 0;
    }

    private void handle_state_unknown(buf_state context)
    {
        context.buffer.mark();
        if(TLSRecord.getContentType(context.buffer) == TLSRecord.HANDSHAKE)
        {
            context.curState = tls_state.RECORD_LAYER;
            context.toRead = TLSRecord.RECORD_HEADER_SIZE;
        }
        else
        {
            context.curState = tls_state.IRRELEVANT;
            context.toRead = 0;
        }
        context.buffer.reset();
    }

    private void handle_state_record_layer(buf_state context)
    {
        short content_type = TLSRecord.getContentType(context.buffer);
        short tls_major_version = TLSRecord.getMajorVersion(context.buffer);
        short tls_minor_version = TLSRecord.getMinorVersion(context.buffer);
        int tls_record_length = TLSRecord.getRecordLength(context.buffer);

        //Log.d(TAG, "Major: " + packet[1+ context.readIndex] + " Minor: " + packet[2 + context.readIndex] + " RecordLength: " + packet[3 + context.readIndex] + " " + packet[4 + context.readIndex]);
        //Log.d(TAG, "Major: " + tls_major_version + " Minor: " + tls_minor_version + " RecordLength: " + tls_record_length);

        context.curState = tls_state.HANDSHAKE_LAYER;
        //Log.d(TAG, "TLS Record Size: " + tls_record_length);
        context.toRead = tls_record_length;
    }

    private void handle_state_handshake_layer(buf_state context, connection_state con)
    {
        int tls_record_bytes = context.toRead;
        //Log.d(TAG, context.buffer.remaining() + " SHould be bigger than: " + tls_record_bytes + " " + context.buffer);
        int handshake_message_length;
        short type;
        while(tls_record_bytes > 0)
        {

            type = TLSHandshake.getHandshakeMessageType(context.buffer);
            handshake_message_length = TLSHandshake.getHandshakeDataLength(context.buffer);
            tls_record_bytes -= handshake_message_length + TLSHandshake.HANDSHAKE_HEADER_SIZE;
            switch(type)
            {
                case TLSHandshake.TYPE_CLIENT_HELLO:
                    Log.d("TAG", "Client Hello");
                    context.toRead = 1;
                    context.curState = tls_state.CLIENT_HELLO_SENT;
                    handle_client_hello(context, con);
                    break;
                case TLSHandshake.TYPE_SERVER_HELLO:
                    Log.d("TAG", "Server Hello");
                    context.toRead = TLSRecord.RECORD_HEADER_SIZE;
                    context.curState = tls_state.RECORD_LAYER;
                    context.buffer.position(context.buffer.position() + handshake_message_length);
                    break;
                case TLSHandshake.TYPE_CERTIFICATE:
                    Log.d("TAG", "Cert");
                    context.toRead = TLSRecord.RECORD_HEADER_SIZE;
                    context.curState = tls_state.RECORD_LAYER;
                    handle_certificate(context, con);
                    break;
                case TLSHandshake.TYPE_SERVER_KEY_EXCHANGE:
                    Log.d("TAG", "Server key exchange");
                    context.toRead = TLSRecord.RECORD_HEADER_SIZE;
                    context.curState = tls_state.RECORD_LAYER;
                    context.buffer.position(context.buffer.position() + handshake_message_length);
                    break;
                case TLSHandshake.TYPE_SERVER_HELLO_DONE:
                    Log.d("TAG", "Server Hello Done");
                    context.toRead = 1;
                    context.curState = tls_state.SERVER_HELLO_DONE_SENT;
                    context.buffer.position(context.buffer.position() + handshake_message_length);
                    break;
                default:
                    Log.d("TAG", "unknown");
                    context.toRead = 0;
                    context.buffer.position(context.buffer.limit());
                    context.curState = tls_state.IRRELEVANT;
                    tls_record_bytes = 0;
                    break;
            }
        }
    }

    private void handle_client_hello(buf_state context, connection_state con)
    {
        TLSHandshake.getClientHelloMajorVersion(context.buffer);
        TLSHandshake.getClientHelloMinorVersion(context.buffer);
        TLSHandshake.getClientHelloRandom(context.buffer);
        short id_length = TLSHandshake.getClientHelloSessionIdLength(context.buffer);
        TLSHandshake.getClientHelloSessionID(context.buffer, id_length);
        int cipher_length = TLSHandshake.getCipherSuiteLength(context.buffer);
        TLSHandshake.getCipherSuites(context.buffer, cipher_length);
        short compression_length = TLSHandshake.getClientHelloCompressionMethodsLength(context.buffer);
        TLSHandshake.getClientHelloCompressionMethods(context.buffer, compression_length);
        int extensions_length = TLSHandshake.getClientHelloExtensionsLength(context.buffer);
        while(extensions_length > 0)
        {
            int extension_type = TLSHandshake.getExtensionType(context.buffer);
            int extension_length = TLSHandshake.getExtensionLength(context.buffer);
            if(extension_type == TLSHandshake.EXTENSION_TYPE_SERVER_NAME)
            {
                con.hostname = TLSHandshake.getClientHelloServerName(context.buffer);
            }
            extensions_length -= extension_length;
        }
    }


    private void handle_certificate(buf_state context, connection_state con)
    {
        final List<X509Certificate> certs = TLSHandshake.getCertificates(context.buffer);
        //Log.d(TAG, "Got Certificate for: " + con.hostname);
        //TODO Check policy engine
    }

    private void handle_state_client_hello_sent(buf_state context)
    {
        context.toRead = 0;
        context.curState = tls_state.IRRELEVANT;
    }

    private void handle_state_server_hello_done_sent(buf_state context)
    {
        context.toRead = 0;
        context.curState = tls_state.IRRELEVANT;
    }
}
