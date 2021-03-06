package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import android.util.Log;

import java.security.cert.X509Certificate;
import java.util.List;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;
import edu.byu.tlsresearch.TrustHub.API.PolicyEngine;
import edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy.TrustHub.buf_state;
import edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy.TrustHub.connection_state;
import edu.byu.tlsresearch.TrustHub.Utils.CertSpoofer;
import edu.byu.tlsresearch.TrustHub.Utils.TLSHandshake;
import edu.byu.tlsresearch.TrustHub.Utils.TLSRecord;

/**
 * Created by sheidbri on 5/22/15.
 */
public class TLSState
{

    public enum tls_state
    {
        UNKNOWN,
        HANDSHAKE_LAYER,
        RECORD_LAYER,
        CLIENT_HELLO_SENT,
        SERVER_HELLO_DONE_SENT,
        IRRELEVANT
    }

    public static void handle(connection_state conState, buf_state buf)
    {
        try
        {
            while (canTransition(buf))
            {
                //Log.d("TLSState", "Start: " + TrustHub.bytesToHex(buf.buffer));
                switch (buf.curState)
                {
                    case UNKNOWN:
                        handle_state_unknown(buf);
                        break;
                    case RECORD_LAYER:
                        handle_state_record_layer(buf);
                        break;
                    case HANDSHAKE_LAYER:
                        handle_state_handshake_layer(buf, conState);
                        break;
                    case CLIENT_HELLO_SENT:
                        handle_state_client_hello_sent(buf);
                        break;
                    case SERVER_HELLO_DONE_SENT:
                        handle_state_server_hello_done_sent(buf);
                        break;
                    case IRRELEVANT:
                        buf.buffer.position(buf.buffer.limit());
                        buf.toRead = 0;
                        break;
                }
            }
        }
        catch (Exception e)
        {
            if (buf != null)
            {
                Log.d("TLSState", "Try catch error");
                buf.curState = tls_state.IRRELEVANT;
            }
            String TAG = "TLSState";
            Log.d(TAG, "Send WHAT THE CRAP: " + e.getMessage() + "\n" + e.toString());
            e.printStackTrace();
        }
    }

    private static boolean canTransition(buf_state state)
    {
        return state.buffer.remaining() >= state.toRead && state.toRead > 0;
    }

    private static void handle_state_unknown(buf_state buf)
    {
        buf.buffer.mark();
        if (TLSRecord.getContentType(buf.buffer) == TLSRecord.HANDSHAKE)
        {
            buf.curState = tls_state.RECORD_LAYER;
            buf.toRead = TLSRecord.RECORD_HEADER_SIZE;
        }
        else
        {
            buf.curState = tls_state.IRRELEVANT;
            buf.toRead = 0;
        }
        buf.buffer.reset();
    }

    private static void handle_state_record_layer(buf_state buf)
    {
        short content_type = TLSRecord.getContentType(buf.buffer);
        short tls_major_version = TLSRecord.getMajorVersion(buf.buffer);
        short tls_minor_version = TLSRecord.getMinorVersion(buf.buffer);
        int tls_record_length = TLSRecord.getRecordLength(buf.buffer);
        switch (content_type)
        {
            case TLSRecord.HANDSHAKE:
                buf.curState = tls_state.HANDSHAKE_LAYER;
                buf.toRead = tls_record_length;
                break;
            default:
                buf.curState = tls_state.IRRELEVANT;
                buf.toRead = 0;
                break;
        }
    }

    private static void handle_state_handshake_layer(buf_state context, connection_state con)
    {
        int tls_record_bytes = context.toRead;
        int handshake_message_length;
        short type;
        while (tls_record_bytes > 0)
        {
            type = TLSHandshake.getHandshakeMessageType(context.buffer);
            handshake_message_length = TLSHandshake.getHandshakeDataLength(context.buffer);
            tls_record_bytes -= handshake_message_length + TLSHandshake.HANDSHAKE_HEADER_SIZE;
            switch (type)
            {
                case TLSHandshake.TYPE_CLIENT_HELLO:
                    context.toRead = 0;
                    context.curState = tls_state.CLIENT_HELLO_SENT;
                    handle_client_hello(context, con);
                    break;
                case TLSHandshake.TYPE_SERVER_HELLO:
                    context.toRead = TLSRecord.RECORD_HEADER_SIZE;
                    context.curState = tls_state.RECORD_LAYER;
                    context.buffer.position(context.buffer.position() + handshake_message_length);
                    break;
                case TLSHandshake.TYPE_CERTIFICATE:
                    context.toRead = TLSRecord.RECORD_HEADER_SIZE;
                    context.curState = tls_state.RECORD_LAYER;
                    handle_certificate(context, con);
                    break;
                case TLSHandshake.TYPE_SERVER_KEY_EXCHANGE:
                    context.toRead = TLSRecord.RECORD_HEADER_SIZE;
                    context.curState = tls_state.RECORD_LAYER;
                    context.buffer.position(context.buffer.position() + handshake_message_length);
                    break;
                case TLSHandshake.TYPE_SERVER_HELLO_DONE:
                    context.toRead = 1;
                    context.curState = tls_state.SERVER_HELLO_DONE_SENT;
                    context.buffer.position(context.buffer.position() + handshake_message_length);
                    break;
                default:
                    context.toRead = TLSRecord.RECORD_HEADER_SIZE;
                    context.curState = tls_state.RECORD_LAYER;
                    context.buffer.position(context.buffer.position() + handshake_message_length);
                    break;
            }
        }
    }

    private static void handle_client_hello(buf_state context, connection_state con)
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
        if (context.buffer.hasRemaining())
        {
            int extensions_length = TLSHandshake.getClientHelloExtensionsLength(context.buffer);
            while (extensions_length > 0)
            {
                int extension_type = TLSHandshake.getExtensionType(context.buffer);
                int extension_length = TLSHandshake.getExtensionLength(context.buffer);
                if (extension_type == TLSHandshake.EXTENSION_TYPE_SERVER_NAME)
                {
                    con.hostname = TLSHandshake.getClientHelloServerName(context.buffer);
                }
                extensions_length -= extension_length;
            }
        }
    }


    private static void handle_certificate(buf_state context, connection_state con)
    {
        final List<X509Certificate> certs = TLSHandshake.getCertificates(context.buffer);
        PluginInterface.POLICY_RESPONSE response = PolicyEngine.getInstance().policy_check(certs);
        switch (response)
        {
            case VALID_PROXY:
                con.proxyState = TrustHub.proxy_state.PROXY;
                con.spoofedStore = CertSpoofer.generateCert(certs.get(0));
                break;
            case INVALID:
                con.proxyState = TrustHub.proxy_state.KILL;
                //TODO mangle Certificate
                break;
            case VALID:
                con.proxyState = TrustHub.proxy_state.NOPROXY;
                break;
        }
    }

    private static void handle_state_client_hello_sent(buf_state context)
    {
        context.toRead = 0;
        context.curState = tls_state.IRRELEVANT;
    }

    private static void handle_state_server_hello_done_sent(buf_state context)
    {
        context.toRead = 0;
        context.curState = tls_state.IRRELEVANT;
    }
}
