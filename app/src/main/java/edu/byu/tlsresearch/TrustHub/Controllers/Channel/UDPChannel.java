package edu.byu.tlsresearch.TrustHub.Controllers.Channel;

import android.util.Log;

import java.io.IOException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;

import edu.byu.tlsresearch.TrustHub.Controllers.FromApp.VPNServiceHandler;
import edu.byu.tlsresearch.TrustHub.Controllers.Socket.IChannelListener;
import edu.byu.tlsresearch.TrustHub.Controllers.Socket.SocketPoller;
import edu.byu.tlsresearch.TrustHub.Controllers.TransportLayer.UDPController;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 1/15/15.
 * <p/>
 * Manages a single UDP Socket
 * Marshalls traffic between UDPController and SocketPoller.
 */
public class UDPChannel implements IChannelListener
{
    private SelectionKey mChannelKey;
    private Connection mContext;
    private long mUsedRecently = System.currentTimeMillis();

    public UDPChannel(Connection context, byte[] packet)
    {
        setmContext(context);
        //InetSocketAddress toConnect = new InetSocketAddress(context.getDestIP(),
        //        context.getDestPort());
        try
        {
            DatagramChannel socket = DatagramChannel.open(); // Should be unconnceted socket
            socket.socket().bind(null);
            VPNServiceHandler.getVPNServiceHandler().protect(socket.socket());
            setmChannelKey(SocketPoller.getInstance().registerChannel(socket, context, this));
        }
        catch (IOException e)
        {
            // TODO: tell the app it can't connect
        }
    }

    public void send(Connection context, byte[] packet)
    {
        this.setSend(context.getDestIP(), context.getDestPort());
        SocketPoller.getInstance().proxySend(mChannelKey, UDPController.stripHeaders(packet));
        mUsedRecently = System.currentTimeMillis();
    }

    @Override
    public void receive(byte[] packet)
    {
        mUsedRecently = System.currentTimeMillis();
        UDPController.receive(packet, this);
    }

    @Override
    public void readFinish()
    {
        this.close();
    }

    @Override
    public void close()
    {
        Log.d("UDPChannel", "UDP Closed " + mContext.toString());
        SocketPoller.getInstance().close(getmChannelKey());
        UDPController.remove(mContext);
    }

    @Override
    public void writeFinish()
    {
        this.close();
    }

    public long isRecentlyUsed()
    {
        return mUsedRecently;
    }

    public void setRecentlyUsed(long set)
    {
        mUsedRecently = set;
    }

    public SelectionKey getmChannelKey()
    {
        return mChannelKey;
    }

    public void setmChannelKey(SelectionKey mChannelKey)
    {
        this.mChannelKey = mChannelKey;
    }

    public Connection getmContext()
    {
        return mContext;
    }

    public void setSend(String newIP, int newPort)
    {
        mContext = new Connection(newIP, newPort, mContext.getClientIP(), mContext.getClientPort());
    }

    public void setmContext(Connection mContext)
    {
        this.mContext = mContext;
    }
}
