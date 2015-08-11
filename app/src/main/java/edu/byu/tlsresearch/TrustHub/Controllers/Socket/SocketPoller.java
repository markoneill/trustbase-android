package edu.byu.tlsresearch.TrustHub.Controllers.Socket;

import android.util.Log;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import edu.byu.tlsresearch.TrustHub.Controllers.Channel.UDPChannel;
import edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy.TrustHub;
import edu.byu.tlsresearch.TrustHub.Controllers.TransportLayer.UDPController;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Manages actual socket connections to the outside world, their read and writes.
 */

public class SocketPoller implements Runnable
{
    private Map<SelectionKey, List<byte[]>> mToWrite;
    private Selector mEpoll;
    public static String TAG = "SocketPoller";

    private static SocketPoller mInstance = null;

    public static SocketPoller getInstance()
    {
        if (mInstance == null)
        {
            try
            {
                mInstance = new SocketPoller();
            } catch (IOException e)
            {
                assert false; // TODO: gracefully fail?
            }
        }
        return mInstance;
    }

    private SocketPoller() throws IOException
    {
        mEpoll = Selector.open();
        mToWrite = new ConcurrentHashMap<SelectionKey, List<byte[]>>();
    }

    public void proxySend(SelectionKey key, byte[] toWrite)
    {
        TrustHub.getInstance().proxyOut(toWrite, key);
    }

    public void noProxySend(SelectionKey key, byte[] toWrite)
    {
        // TODO: syncronize reads and writes to this buffer
        mToWrite.get(key).add(toWrite);
    }

    private void proxyRead(SelectionKey key, ByteBuffer packet, int length)
    {
        byte[] toRead = new byte[packet.remaining()];
        packet.get(toRead);
        TrustHub.getInstance().proxyIn(toRead, key);
        packet.clear();
    }

    private void noProxyRead(SelectionKey key, ByteBuffer packet, int length)
    {
        byte[] toRead = new byte[packet.remaining()];
        packet.get(toRead);
        ((IChannelListener) key.attachment()).receive(toRead);
        packet.clear();
    }

    public SelectionKey registerChannel(SelectableChannel toRegister, Connection con, IChannelListener writeBack)
    {
        SelectionKey toAdd;
        try
        {
            toRegister.configureBlocking(false);
            synchronized (this)
            {
                mEpoll.wakeup();
                toAdd = toRegister.register(mEpoll, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
                toAdd.attach(writeBack);
                mToWrite.put(toAdd, new ArrayList<byte[]>());
            }
            return toAdd;
        } catch (Exception e)
        {
            return null;
        }
    }

    public boolean close(SelectionKey key)
    {
        if (key.isValid()) {
            key.interestOps(0);
            key.cancel();
        }
        mToWrite.remove(key);
        try
        {
            key.channel().close();
        } catch (IOException e)
        {
            Log.e(TAG, "Socket Close fail");
            return false;
        }
        return true;
    }

    @Override
    public void run()
    {
        java.lang.System.setProperty("java.net.preferIPv4Stack", "true");
        java.lang.System.setProperty("java.net.preferIPv6Addresses", "false");
        ByteBuffer packet = ByteBuffer.allocate(32767);
        int length = 0;

        while (true)
        {
            try
            {
                if (mEpoll.select() != 1)
                {
                    synchronized (this)
                    {
                    } // used to stop this from blocking immediately when wakeup from register is called
                    Set<SelectionKey> selectedKeys = mEpoll.selectedKeys();
                    Iterator<SelectionKey> keyIterator = selectedKeys.iterator();
                    while (keyIterator.hasNext())
                    {
                        SelectionKey key = keyIterator.next();
                        // READ FROM SOCKET
                        if(!key.isValid())
                            continue;
                        if (key.isReadable())
                        {
                            packet.clear();
                            try
                            {
                                if (key.channel() instanceof SocketChannel)
                                {
                                    length = ((SocketChannel) key.channel()).read(packet);
                                }
                                else if (key.channel() instanceof DatagramChannel)
                                {

                                    InetSocketAddress from =(InetSocketAddress) ((DatagramChannel) key.channel()).receive(packet);
                                    ((UDPChannel) key.attachment()).setSend(from.getAddress().toString().replace("/", ""), from.getPort());
                                    length = packet.position();
                                    Log.d("UDP","Received: " + length);
                                }
                                if (length > 0)
                                {
                                    packet.flip();
                                    proxyRead(key, packet, length);
                                }
                                if (length == -1)
                                {
                                    key.interestOps(key.interestOps() & ~SelectionKey.OP_READ);
                                    ((IChannelListener) key.attachment()).readFinish();
                                }
                            } catch (ClosedChannelException e)
                            {
                                ((IChannelListener) key.attachment()).close();
                            }
                            catch (SocketException e)
                            {
                                ((IChannelListener) key.attachment()).close();
                            }
                            length = 0;
                        }
                        // WRITE TO SOCKET
                        else if (key.isWritable())
                        {
                            handleWrite(key);
                        }
                        keyIterator.remove();
                    }
                }
            } catch (IOException e)
            {
                e.printStackTrace();
            }
            UDPController.markAndSweep();
        }
    }

    private void handleWrite(SelectionKey key) throws IOException
    {
        //TODO This errors sometimes withh null object reference
        // I think it is perhaps running out of memory and I can't make a new one
        if (!mToWrite.get(key).isEmpty()) //TODO: switch this back to while?
        {
            byte[] toWrite = mToWrite.get(key).get(0);
            ByteBuffer writer = ByteBuffer.wrap(new byte[toWrite.length]);
            writer.put(toWrite);
            writer.flip();
            int totalWrote = 0;
            if (key.channel() instanceof SocketChannel)
            {
                try
                {
                    totalWrote = ((SocketChannel) key.channel()).write(writer);
                } catch (SocketException e)
                {
                    key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                    ((IChannelListener) key.attachment()).writeFinish();
                    return;
                }
            } else if (key.channel() instanceof DatagramChannel)
            {
                try
                {
                    UDPChannel attachment = (UDPChannel) key.attachment();
                    InetSocketAddress toSend = new InetSocketAddress(attachment.getmContext().getDestIP(),
                            attachment.getmContext().getDestPort());
                    totalWrote = ((DatagramChannel) key.channel()).send(writer, toSend);
                    ((UDPChannel) key.attachment()).setRecentlyUsed(System.currentTimeMillis());
                }
                catch(IOException e)
                {
                    //continue;
                }
            }
            if (totalWrote == toWrite.length)
            {
                mToWrite.get(key).remove(0);
            } else
            {
                Log.d(TAG, "Not full write: " + totalWrote);
                mToWrite.get(key).set(0, Arrays.copyOfRange(mToWrite.get(key).get(0), totalWrote, toWrite.length));
               // key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                //break; // Wasn't able to receive anymore so break out //TODO: if switched back uncomment this
            }
        }
    }
}
