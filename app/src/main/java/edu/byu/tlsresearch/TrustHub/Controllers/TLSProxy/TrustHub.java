package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import android.util.Log;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.security.KeyStore;
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
    private Map<SelectionKey, connection_state> mStates = new HashMap<SelectionKey, connection_state>();

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
        public SSLProxy myProxy;
        public KeyStore spoofedStore;

        public connection_state(Connection context)
        {
            sendBuffer = new buf_state();
            recvBuffer = new buf_state();
            hostname = context.getDestIP();
            proxyState = proxy_state.START;
        }

        public void startProxy(SelectionKey key) throws Exception
        {
            myProxy = new SSLProxy(key, spoofedStore, "password");
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

    private TrustHub() {}

    private connection_state getState(SelectionKey context)
    {
        if (!mStates.containsKey(context))
        {
            mStates.put(context, new connection_state(((TCPChannel)context.attachment()).getmContext()));
        }
        return mStates.get(context);
    }

    public void close(SelectionKey context)
    {
        if(mStates.containsKey(context))
        {
            mStates.remove(context);
        }
    }

    public void proxyOut(byte[] toWrite, SelectionKey key)
    {
        byte[] reallySend = null;
        if(!(key.attachment() instanceof TCPChannel))
        {
            reallySend = toWrite;
        }
        else
        {
            Connection conn = ((TCPChannel) key.attachment()).getmContext();
            connection_state conState = getState(key);
            if (conState.sendBuffer.curState != TLSState.tls_state.IRRELEVANT) // Is it TLS?
            {
                conState.sendBuffer.buffer.put(toWrite);
                conState.sendBuffer.buffer.flip();
                if (conState.sendBuffer.curState == TLSState.tls_state.CLIENT_HELLO_SENT)
                {
                    switch (conState.proxyState)
                    {
                        case NOPROXY:
                            // We no longer care about this connection
                            conState.sendBuffer.curState = TLSState.tls_state.IRRELEVANT;
                            // TODO delete the buffer?
                            reallySend = toWrite; // Don't want to use buffer because
                            // ClientHello is in there
                            break;
                        case PROXY:
                            byte[] proxySend = new byte[conState.sendBuffer.buffer.remaining()];
                            conState.sendBuffer.buffer.get(proxySend); // Get all the handshake data
                            try
                            {
                                conState.myProxy.send(proxySend);
                            } catch (SSLException e)
                            {
                                Log.e(TAG, "Proxy Send failed: " + e);
                                e.printStackTrace();
                            }
                            break;
                        case KILL:
                            Log.e(TAG, "Should've sent a bad cert why are we sending crap still?");
                            break;
                        case START:
                            // Such as session renegotiation crap (already put in buffer)
                            reallySend = toWrite;
                            break;
                    }
                } else
                {
                    conState.sendBuffer.buffer.mark();
                    TLSState.handle(conState, conState.sendBuffer);
                    conState.sendBuffer.buffer.reset();
                    if (conState.sendBuffer.curState != TLSState.tls_state.CLIENT_HELLO_SENT &&
                            conState.sendBuffer.curState != TLSState.tls_state.IRRELEVANT)
                    {
                        //Didn't get the whole clientHello yet so
                        //pretend we haven't gotten anything lolol
                        conState.sendBuffer.curState = TLSState.tls_state.UNKNOWN;
                        conState.sendBuffer.toRead = 1;
                    } else
                    {
                        reallySend = new byte[conState.sendBuffer.buffer.remaining()];
                        conState.sendBuffer.buffer.mark(); // Want to save ClientHello
                        conState.sendBuffer.buffer.get(reallySend);
                        conState.sendBuffer.buffer.reset();
                    }
                }
                conState.sendBuffer.buffer.compact();
            } else
            {
                reallySend = toWrite;
            }
        }
        if (reallySend != null)
        {
            Log.d(TAG, "Done");
            SocketPoller.getInstance().noProxySend(key, reallySend);
        }
    }

    public void proxyIn(byte[] packet, SelectionKey key)
    {
        byte[] reallyReceive = null;
        if(!(key.attachment() instanceof TCPChannel))
        {
            reallyReceive = packet;
        }
        else
        {
            // Get connection Info
            Connection conn = ((TCPChannel) key.attachment()).getmContext();
            connection_state conState = getState(key);

            if (conState.recvBuffer.curState != TLSState.tls_state.IRRELEVANT) // Is it tls?
            {
                // Add packet to queue
                conState.recvBuffer.buffer.put(packet);
                conState.recvBuffer.buffer.flip();
                // If server hasn't finished handshake
                if (conState.recvBuffer.curState != TLSState.tls_state.SERVER_HELLO_DONE_SENT)
                {
                    // Don't want the client to know anything until we have it all
                    conState.recvBuffer.buffer.mark();
                    // update the state
                    TLSState.handle(conState, conState.recvBuffer);
                    // revert back to where we were
                    conState.recvBuffer.buffer.reset();
                }
                // TLSState.handle could've changed us to this state
                if (conState.recvBuffer.curState == TLSState.tls_state.SERVER_HELLO_DONE_SENT)
                {
                    //Policy Engine should've made a decision
                    switch (conState.proxyState)
                    {
                        case NOPROXY:
                            //No longer care about the connection
                            conState.recvBuffer.curState = TLSState.tls_state.IRRELEVANT;
                            //Should send everything to the ServerHelloDone
                            reallyReceive = new byte[conState.recvBuffer.buffer.remaining()];
                            conState.recvBuffer.buffer.get(reallyReceive);
                            //TODO delete the buffer?
                            break;
                        case PROXY:
                            if (conState.myProxy == null)
                            {
                                try
                                {
                                    // Dump the Server responses and restart the connection
                                    // We compact at end so just set to limit
                                    conState.recvBuffer.buffer.position(conState.recvBuffer.buffer.limit());
                                    key = ((TCPChannel) key.attachment()).replaceChannel();
                                    // Start of proxying
                                    conState.startProxy(key);
                                    // Send the client Hello
                                    conState.sendBuffer.buffer.flip();
                                    byte[] clientHello = new byte[conState.sendBuffer.buffer.remaining()];
                                    conState.sendBuffer.buffer.get(clientHello);
                                    conState.sendBuffer.buffer.compact();
                                    conState.myProxy.send(clientHello);
                                    conState.myProxy.receive(new byte[0]); //Kickstart the proxy
                                } catch (SSLException e)
                                {
                                    Log.e(TAG, "Send clientHello failed: " + e.getMessage());
                                    e.printStackTrace();
                                } catch (IOException e)
                                {
                                    Log.e(TAG, "Unable to open new socket: " + e.getMessage());
                                } catch (Exception e)
                                {
                                    Log.e(TAG, "Proxy failed: " + e.getMessage());
                                    e.printStackTrace();
                                }
                            } else
                            {
                                byte[] proxyReceive = new byte[conState.recvBuffer.buffer.remaining()];
                                conState.recvBuffer.buffer.get(proxyReceive); // Get all the handshake data
                                // i.e. ClientHello to proxy
                                try
                                {
                                    conState.myProxy.receive(proxyReceive);
                                } catch (SSLException e)
                                {
                                    Log.e(TAG, "Proxy Receive failed: " + e.getMessage());
                                    e.printStackTrace();
                                }
                            }

                            break;
                        case KILL:
                            //TODO replaceCert
                            break;
                        case START:
                            //TODO perhaps have to have a listener if policy engine needs to be asynchronous
                            Log.e(TAG, "Policy Engine should've made a decision");
                            break;
                    }
                } else
                {
                    if (conState.recvBuffer.curState == TLSState.tls_state.IRRELEVANT)
                    {
                        reallyReceive = new byte[conState.recvBuffer.buffer.remaining()];
                        conState.recvBuffer.buffer.get(reallyReceive);
                        //TODO delete buffer?
                    } else
                    {
                        //Haven't got it all yet so wait
                        conState.recvBuffer.curState = TLSState.tls_state.UNKNOWN;
                        conState.recvBuffer.toRead = 1;
                    }
                }
                conState.recvBuffer.buffer.compact();
            } else
            {
                reallyReceive = packet;
            }
        }
        if (reallyReceive != null)
        {
            ((IChannelListener) key.attachment()).receive(reallyReceive);
        }
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes)
    {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++)
        {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String bytesToHex(ByteBuffer bd)
    {
        ByteBuffer bb = bd.duplicate();
        byte[] b = new byte[bb.remaining()];
        bb.get(b);
        return bytesToHex(b);
    }
}
