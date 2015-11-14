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
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

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
    private ReentrantLock mEpollLock = new ReentrantLock();

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
        if(toWrite != null) //TODO dont want to check if is valid
        {
            try
            {
                //Log.d(TAG, "Send " + key.toString());
                //Log.d(TAG, "1 queue lock: " + mQueueLock.isHeldByCurrentThread());
                mEpollLock.lock();
                mEpoll.wakeup();
                mWriteQueue.get(key).add(toWrite);
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
            }
            catch(NullPointerException e)
            {
                e.printStackTrace(); //TODO remove this
            }
            finally
            {
                mEpollLock.unlock();
            }
            //Log.d(TAG, "1 queue unlock");
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
        //Log.d(TAG, "Receive " + key.toString());
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
            //Log.d(TAG, "2 epoll lock: " + mEpollLock.isHeldByCurrentThread());
            mEpollLock.lock();
            mEpoll.wakeup();
            toAdd = toRegister.register(mEpoll, 0);
            toAdd.attach(writeBack);
            mWriteQueue.put(toAdd, new LinkedBlockingQueue<byte[]>());
            mEpollLock.unlock();
            //Log.d(TAG, "2 epoll unlock");
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

        //Log.d(TAG, "4 epoll lock: " + mEpollLock.isHeldByCurrentThread());
        mEpollLock.lock();
        mEpoll.wakeup();
        if(key.isValid())
        {
            key.interestOps(0);
        }
        //Log.d(TAG, "cancelAKJFPKADJPOSDJPG:LJSD:LGFJDS:LGJS:DLG " + key.toString());
        key.cancel();
        try
        {
            if(key.channel().isOpen())
            {
                key.channel().close();
            }
        } catch (IOException e)
        {
            Log.e(TAG, "Socket Close fail");
        }
        finally
        {
            //Log.d(TAG, "4 epoll unlock");
            mEpollLock.unlock();
            mWriteQueue.remove(key);
            return true;
        }
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
                if (mEpoll.select() > 0)
                {
                   // Log.d(TAG, "End Polling");
                    //Log.d(TAG, "" + mWriteQueue.size());
                    mEpollLock.lock();
                    mEpollLock.unlock();
                    Set<SelectionKey> selectedKeys = mEpoll.selectedKeys();
                    Iterator<SelectionKey> keyIterator = selectedKeys.iterator();
                    while (keyIterator.hasNext())
                    {
                        SelectionKey key = keyIterator.next();
                        //Log.d(TAG, "poll " + key.toString());
                        // READ FROM SOCKET
                       // Log.d(TAG, "Poller: " + key.toString());
                        if(!key.isValid())
                            continue;
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
                    mEpollLock.lock(); // used to stop this from blocking immediately when wakeup from register is called
                    mEpollLock.unlock();
                }
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            finally
            {
                UDPController.markAndSweep();
            }
        }
    }

    private void handleRead(SelectionKey key) throws IOException
    {
//        Log.d(TAG, key.toString() + " Reading");

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
                //Log.d(TAG, "canceld? " + key.toString());
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

        // I think it is perhaps running out of memory and I can't make a new one
        if (!mWriteQueue.get(key).isEmpty())
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
            if(key.channel() instanceof SocketChannel && key.interestOps() == 0)
            {
                ((TCPChannel) key.attachment()).close();
            }
        }
    }
}
