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
import java.util.Iterator;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

import edu.byu.tlsresearch.TrustHub.Controllers.Channel.TCPChannel;
import edu.byu.tlsresearch.TrustHub.Controllers.Channel.UDPChannel;
import edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy.TrustHub;
import edu.byu.tlsresearch.TrustHub.Controllers.TransportLayer.UDPController;
import edu.byu.tlsresearch.TrustHub.Utils.TCPHeader;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Manages actual socket connections to the outside world, their read and writes.
 */

public class SocketPoller implements Runnable
{
    private Map<SelectionKey, Queue<byte[]>> mWriteQueue;
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
            }
            catch (IOException e)
            {
                assert false; // TODO: gracefully fail?
            }
        }
        return mInstance;
    }

    private SocketPoller() throws IOException
    {
        mEpoll = Selector.open();
        mWriteQueue = new ConcurrentHashMap<SelectionKey, Queue<byte[]>>();
    }

    public void noProxySend(SelectionKey key, byte[] toWrite)
    {
        if(toWrite != null)
        {
            Log.d(TAG, key.toString() + " " + TrustHub.bytesToHex(toWrite));
            synchronized (this)
            {
                mEpoll.wakeup();
                mWriteQueue.get(key).add(toWrite);
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
            }
            //Log.d(TAG, "Added to Queue");
        }
    }

    public void proxySend(SelectionKey key, byte[] toWrite)
    {
        TrustHub.getInstance().proxyOut(toWrite, key);
        //Log.d(TAG, "Finished Send");
    }

    private void noProxyReceive (SelectionKey key, ByteBuffer packet, int length)
    {
        byte[] toRead = new byte[packet.remaining()];
        packet.get(toRead);
        if(toRead == null)
        {
            ((IChannelListener) key.attachment()).receive(toRead);
            packet.clear();
        }
    }

    private void proxyRead(SelectionKey key, ByteBuffer packet, int length)
    {
        byte[] toRead = new byte[packet.remaining()];
        packet.get(toRead);
        TrustHub.getInstance().proxyIn(toRead, key);
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
                toAdd = toRegister.register(mEpoll, 0);
                toAdd.attach(writeBack);
                mWriteQueue.put(toAdd, new LinkedBlockingQueue<byte[]>());
            }
            return toAdd;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    public boolean close(SelectionKey key)
    {
        synchronized (this)
        {
            if(key.isValid())
            {
                key.interestOps(0);
            }
            key.cancel();
            try
            {
                key.channel().close();
            } catch (IOException e)
            {
                Log.e(TAG, "Socket Close fail");
                return false;
            }
            mEpoll.wakeup();
            mWriteQueue.remove(key);
            try{
                Log.d(TAG, "removed: " + key.toString());
                throw new Exception();
            }
            catch(Exception e)
            {
                e.printStackTrace();
            }
        }
        return true;
    }

    @Override
    public void run()
    {
        java.lang.System.setProperty("java.net.preferIPv4Stack", "true");
        java.lang.System.setProperty("java.net.preferIPv6Addresses", "false");

        while (true)
        {
            try
            {

                //Log.d(TAG, "Start Polling");
                if (mEpoll.select() > 0)
                {

                   // Log.d(TAG, "End Polling");
                    //Log.d(TAG, "" + mWriteQueue.size());
                    synchronized (this)
                    {
                    } // used to stop this from blocking immediately when wakeup from register is called
                    Set<SelectionKey> selectedKeys = mEpoll.selectedKeys();
                    Iterator<SelectionKey> keyIterator = selectedKeys.iterator();
                    while (keyIterator.hasNext())
                    {
                        SelectionKey key = keyIterator.next();
                        // READ FROM SOCKET
                        if(key.isConnectable())
                        {
                            try
                            {
                                ((SocketChannel) key.channel()).finishConnect();
                                key.interestOps((key.interestOps() | SelectionKey.OP_READ) & ~SelectionKey.OP_CONNECT);
                            }
                            catch(Exception e)
                            {
                                Log.d(TAG, "failed connect");
                                ((TCPChannel) key.attachment()).receive(new byte[0], TCPHeader.RST);
                                ((TCPChannel) key.attachment()).close();
                            }
                        }
                        else if (key.isReadable())
                        {
                            handleRead(key);
                        }
                        else if (key.isWritable())
                        {
                            handleWrite(key);
                        }
                        keyIterator.remove();
                    }
                }
                else
                {
                    synchronized (this)
                    {
                    } // used to stop this from blocking immediately when wakeup from register is called
                }
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            UDPController.markAndSweep();
        }
    }

    private void handleRead(SelectionKey key) throws IOException
    {
        //Log.d(TAG, key.toString() + " Reading");
        ByteBuffer packet = ByteBuffer.allocate(32767);
        int length = 0;
        try
        {
            if (key.channel() instanceof SocketChannel)
            {
                length = ((SocketChannel) key.channel()).read(packet);
            }
            else if (key.channel() instanceof DatagramChannel)
            {
                InetSocketAddress from = (InetSocketAddress) ((DatagramChannel) key.channel()).receive(packet);
                ((UDPChannel) key.attachment()).setSend(from.getAddress().toString().replace("/", ""), from.getPort());
                length = packet.position();
            }
            if (length > 0)
            {
                packet.flip();
                this.proxyRead(key, packet, length);
            }
            if (length == -1)
            {
                key.interestOps(key.interestOps() & ~SelectionKey.OP_READ);
                ((IChannelListener) key.attachment()).readFinish();
            }
        }
        catch (ClosedChannelException e)
        {
            ((IChannelListener) key.attachment()).close();
        }
        catch (SocketException e)
        {
            ((IChannelListener) key.attachment()).close();
        }
        length = 0;
    }

    private void handleWrite(SelectionKey key) throws IOException
    {
        //Log.d(TAG, key.toString() + " Writing");
        synchronized (this)
        {
            //TODO This errors sometimes with null object reference
            // I think it is perhaps running out of memory and I can't make a new one
            if (!mWriteQueue.get(key).isEmpty()) //TODO: switch this back to while?
            {
                byte[] toWrite = mWriteQueue.get(key).remove();
                ByteBuffer writer = ByteBuffer.wrap(new byte[toWrite.length]);
                writer.put(toWrite);
                writer.flip();
                while (writer.hasRemaining())
                {
                    if (key.channel() instanceof SocketChannel)
                    {
                        ((SocketChannel) key.channel()).write(writer);
                    } else if (key.channel() instanceof DatagramChannel)
                    {
                        UDPChannel attachment = (UDPChannel) key.attachment();
                        InetSocketAddress toSend = new InetSocketAddress(attachment.getmContext().getDestIP(),
                                attachment.getmContext().getDestPort());
                        ((DatagramChannel) key.channel()).send(writer, toSend);
                        ((UDPChannel) key.attachment()).setRecentlyUsed(System.currentTimeMillis());
                    }
                }
            }
            if(mWriteQueue.get(key).isEmpty())
            {
                key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
            }
        }
    }
}
