package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import android.util.Log;

import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLException;

import edu.byu.tlsresearch.TrustHub.Controllers.Channel.TCPChannel;
import edu.byu.tlsresearch.TrustHub.Controllers.Socket.IChannelListener;
import edu.byu.tlsresearch.TrustHub.Controllers.Socket.SocketPoller;
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

    public enum proxy_state
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
        byte[] reallySend = null;
        if(conState.sendBuffer.curState != TLSState.tls_state.IRRELEVANT) // Is it TLS?
        {
            conState.sendBuffer.buffer.put(toWrite);
            conState.sendBuffer.buffer.flip();
            if(conState.sendBuffer.curState == TLSState.tls_state.CLIENT_HELLO_SENT)
            {
                switch(conState.proxyState)
                {
                    case NOPROXY:
                        // We no longer care about this connection
                        conState.sendBuffer.curState = TLSState.tls_state.IRRELEVANT;
                        // TODO delete the buffer?
                        reallySend = toWrite;
                        break;
                    case PROXY:
                        //TODO proxy handshake should've already taken place
                        Log.d(TAG, "Proxy");
                        break;
                    case KILL:
                        Log.e(TAG, "Should've sent a bad cert why are we sending crap still?");
                        break;
                    case START:
                        Log.e(TAG, "Shouldn't send anything after ClientHello " +
                                    "and before ServerHellodDone");
                        break;
                }
            }
            else
            {
                conState.sendBuffer.buffer.mark();
                TLSState.handle(conState, conState.sendBuffer);
                conState.sendBuffer.buffer.reset();
                if(conState.sendBuffer.curState != TLSState.tls_state.CLIENT_HELLO_SENT &&
                        conState.sendBuffer.curState != TLSState.tls_state.IRRELEVANT)
                {
                    //Didn't get the whole clientHello yet so
                    //pretend we haven't gotten anything lolol
                    Log.d(TAG, "Not whole ClientHello");
                    conState.sendBuffer.curState = TLSState.tls_state.UNKNOWN;
                }
                else
                {
                    reallySend = new byte[conState.sendBuffer.buffer.remaining()];
                    conState.sendBuffer.buffer.mark(); // Want to save ClientHello
                    conState.sendBuffer.buffer.get(reallySend);
                    conState.sendBuffer.buffer.reset();
                }
            }
            conState.sendBuffer.buffer.compact();
        }
        else
        {
            reallySend = toWrite;
        }
        if(reallySend != null)
        {
            SocketPoller.getInstance().noProxySend(key, reallySend);
        }
    }

    public void proxyIn(byte[] packet, SelectionKey key)
    {
        Connection conn = ((TCPChannel) key.attachment()).getmContext();
        connection_state conState = getState(conn);
        byte[] reallyReceive = null;
        if(conState.recvBuffer.curState != TLSState.tls_state.IRRELEVANT)
        {
            conState.recvBuffer.buffer.put(packet);
            conState.recvBuffer.buffer.flip();
            if(conState.recvBuffer.curState != TLSState.tls_state.SERVER_HELLO_DONE_SENT)
            {
                //Don't want the client to know anything until we have it all
                conState.recvBuffer.buffer.mark();
                TLSState.handle(conState, conState.recvBuffer);
                conState.recvBuffer.buffer.reset();
            }
            // TLSState.handle could've changed us to this state
            if(conState.recvBuffer.curState == TLSState.tls_state.SERVER_HELLO_DONE_SENT)
            {
                //Policy Engine should've made a decision
                switch(conState.proxyState)
                {
                    case NOPROXY:
                        //No longer care about the connection
                        conState.recvBuffer.curState = TLSState.tls_state.IRRELEVANT;
                        //Should send everything to the ServerHelloDone
                        reallyReceive = new byte[conState.recvBuffer.buffer.remaining()];
                        //TODO delete the buffer?
                        break;
                    case PROXY:
                        //TODO Handshake
                        break;
                    case KILL:
                        //TODO replaceCert
                        break;
                    case START:
                        //TODO perhaps have to have a listener if policy engine needs to be asynchronous
                        Log.e(TAG, "Policy Engine should've made a decision");
                        break;
                }
            }
            else
            {
                //Haven't got it all yet so wait
                conState.recvBuffer.curState = TLSState.tls_state.UNKNOWN;
            }
            conState.recvBuffer.buffer.compact();
        }
        else
        {
            reallyReceive = packet;
        }
        if(reallyReceive != null)
        {
            ((IChannelListener) key.attachment()).receive(packet);
        }
    }
}
