package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import android.util.Log;

import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLException;

import edu.byu.tlsresearch.TrustHub.Controllers.Channel.TCPChannel;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 5/29/15.
 */
public class TrustHub
{
    private String TAG = "TrustHub";
    private TLSState tls_state_handler = new TLSState();
    private Map<Connection, connection_state> mStates = new HashMap<>();

    private static TrustHub mInstance;

    private enum proxy_state
    {
        START,
        KILL,
        NOPROXY,
        PROXY
    }

    public class buf_state
    {
        public ByteBuffer buffer;
        public int toRead;
        public TLSState.tls_state curState;
        public buf_state()
        {
            buffer = ByteBuffer.allocate(65535); //TODO Make this not so big and check overflows
            curState = TLSState.tls_state.UNKNOWN;
            toRead = 1;
        }
    }

    public class connection_state
    {
        public buf_state sendBuffer;
        public buf_state recvBuffer;
        public String hostname;
        public proxy_state proxyState;
        private SSLProxy myProxy;

        public connection_state(Connection context)
        {
            sendBuffer = new buf_state();
            recvBuffer = new buf_state();
            hostname = context.getDestIP();
        }

        private SSLProxy getProxy() throws Exception
        {
            if(myProxy == null)
            {
                SSLProxy toReturn = new SSLProxy();
            }
            return myProxy;
        }
    }

    public static TrustHub getInstance()
    {
        if (mInstance == null)
        {
            mInstance = new TrustHub();
        }
        return mInstance;
    }


    public connection_state getState(Connection context)
    {
        if(!mStates.containsKey(context))
        {
            mStates.put(context, new connection_state(context));
        }
        return mStates.get(context);
    }

    public void proxyOut(byte[] toWrite, SelectionKey key)
    {
        Connection conn = ((TCPChannel) key.attachment()).getmContext();
        connection_state conState = getState(conn);
        if(conState.sendBuffer.curState != TLSState.tls_state.IRRELEVANT)
        {
            conState.sendBuffer.buffer.put(toWrite);
            conState.sendBuffer.buffer.flip();
            TLSState.handle(conState, conState.sendBuffer);
            conState.sendBuffer.buffer.compact();
        }
    }

    public void proxyIn(byte[] packet, SelectionKey key)
    {
        Connection conn = ((TCPChannel) key.attachment()).getmContext();
        connection_state conState = getState(conn);
        if(conState.recvBuffer.curState != TLSState.tls_state.IRRELEVANT)
        {
            conState.recvBuffer.buffer.put(packet);
            conState.recvBuffer.buffer.flip();
            TLSState.handle(conState, conState.recvBuffer);
            conState.recvBuffer.buffer.compact();
        }
    }
}
