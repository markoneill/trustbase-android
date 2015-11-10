package edu.byu.tlsresearch.TrustHub.Controllers.Channel;

import android.util.Log;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

import edu.byu.tlsresearch.TrustHub.Controllers.FromApp.VPNServiceHandler;
import edu.byu.tlsresearch.TrustHub.Controllers.Socket.IChannelListener;
import edu.byu.tlsresearch.TrustHub.Controllers.Socket.SocketPoller;
import edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy.TrustHub;
import edu.byu.tlsresearch.TrustHub.Controllers.TransportLayer.TCPController;
import edu.byu.tlsresearch.TrustHub.Utils.TCPHeader;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 1/15/15.
 * <p/>
 * Manages a TCP Socket (mChannelKey) keeping track of SEQ and ACK numbers states of connections.
 * Marshalls traffic between the TCPController and the SocketPoller.
 * Traffic going to SocketPoller is sent through TCBState (mState).
 */
public class TCPChannel implements IChannelListener
{
    private SelectionKey mChannelKey;
    private Connection mContext;
    private long toSEQ = 0;
    private long toACK = 0;
    private ITCBState mState;
    private final String TAG = "TCPChannel";

    public TCPChannel(Connection context, byte[] packet) throws IOException
    {
        mContext = context;
        toACK = TCPHeader.getSequenceNumber(packet);
        toSEQ = 0;
        InetSocketAddress toConnect = new InetSocketAddress(mContext.getDestIP(),
                mContext.getDestPort());
        SocketChannel socket = SocketChannel.open();
        VPNServiceHandler.getVPNServiceHandler().protect(socket.socket());
        mChannelKey = SocketPoller.getInstance().registerChannel(socket, mContext, this);

        if(!socket.connect(toConnect))
        {
            mChannelKey.interestOps(SelectionKey.OP_CONNECT);
        }
        else
        {
            mChannelKey.interestOps(SelectionKey.OP_READ);
        }
        mState = TCBState.START;
        //Log.d(TAG, "Open: " + this.getmContext().toString());
    }

    public SelectionKey replaceChannel() throws IOException
    {
        //Log.d(TAG, "Replace channel: " + mChannelKey.toString());
        SocketPoller.getInstance().close(mChannelKey);
        //TODO close the original one
        InetSocketAddress toConnect = new InetSocketAddress(mContext.getDestIP(),
                mContext.getDestPort());
        SocketChannel socket = SocketChannel.open();
        VPNServiceHandler.getVPNServiceHandler().protect(socket.socket());
        mChannelKey = SocketPoller.getInstance().registerChannel(socket, mContext, this);
        //Log.d(TAG, "With: " + mChannelKey.toString());
        if(!socket.connect(toConnect))
        {
            mChannelKey.interestOps(SelectionKey.OP_CONNECT);
        }
        else
        {
            mChannelKey.interestOps(SelectionKey.OP_READ);
        }
        return mChannelKey;
    }

    public void send(byte[] transport)
    {
        //Log.d(TAG, this.getmChannelKey().toString() + " Send: " + TCPHeader.getFlags(transport) + " Seq " + this.getACK() + " ACK: " + this.getSEQ());
//        int flags = TCPHeader.getFlags(transport);
//        if((flags & TCPHeader.FIN) > 0)
//        {
//            Log.d(TAG, "FINned: " + this.getmContext().toString());
//        }
        synchronized (this)//SEQ gets updated after the receive and since send is on different thread it could be used before we properly incrememnt it
        {
            this.mState.send(this, transport);
        }
    }

    @Override
    public void receive(byte[] payload)
    {
        receive(payload, TCPHeader.ACK | TCPHeader.PSH);
    }

    public void receive(byte[] payload, int flags)
    {
        //Log.d(TAG, this.getmChannelKey().toString() + " Received: flag: " + flags + " Seq " + this.getSEQ() + " ACK: " + this.getACK());
        if (payload == null) // Listeners in communicator can do NULL then nothing will be sent back
            return;
        synchronized (this) //SEQ gets updated after the receive and since send is on different thread it could be used before we properly incrememnt it
        {
            TCPController.receive(payload, this, flags);
            this.toSEQ += payload.length;
            if (payload.length == 0 && (flags & TCPHeader.FIN) != 0)
                this.toSEQ += 1;
        }
    }

    @Override
    public void close()
    {
        //Log.d(TAG, "Closed: " + this.getmChannelKey().toString());
        synchronized (this)
        {
            SocketPoller.getInstance().close(this.getmChannelKey());
            TrustHub.getInstance().close(this.getmContext());
            TCPController.remove(this.getmContext());
        }
    }

    @Override
    public void readFinish()
    {
        synchronized (this)//SEQ gets updated after the receive and since send is on different thread it could be used before we properly increment it
        {
            TCPController.receive(new byte[0], this, TCPHeader.FIN);
            this.toSEQ += 1;
            if(this.mState != TCBState.FIN_WAIT1) // If we are in FIN_WAIT1 we should send one more ack back
            {
                this.mState = TCBState.CLOSE_WAIT;
            }
        }
    }

    @Override
    public void writeFinish()
    {
        synchronized (this)
        {
            TCPController.receive(new byte[0], this, TCPHeader.RST);
            this.close();
        }
    }


    public SelectionKey getmChannelKey()
    {
        synchronized (this)
        {
            return mChannelKey;
        }
    }

    public long getSEQ()
    {
        synchronized (this)
        {
            return toSEQ;
        }
    }

    public void setSEQ(long toSEQ)
    {
        synchronized (this)
        {
            this.toSEQ = toSEQ;
        }
    }

    public long getACK()
    {
        synchronized (this)
        {
            return toACK;
        }
    }

    public void setACK(long toACK)
    {
        synchronized (this)
        {
            this.toACK = toACK;
        }
    }

    public ITCBState getmState()
    {
        synchronized (this)
        {
            return mState;
        }
    }

    public void setmState(ITCBState mState)
    {
        synchronized (this)
        {
            this.mState = mState;
        }
    }

    public Connection getmContext()
    {
        synchronized (this)
        {
            return mContext;
        }
    }
}
