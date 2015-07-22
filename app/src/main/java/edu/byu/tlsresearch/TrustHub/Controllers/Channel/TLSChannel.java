package edu.byu.tlsresearch.TrustHub.Controllers.Channel;

/**
 * Created by sheidbri on 5/29/15.
 */
public class TLSChannel implements IChannel
{
    private TCPChannel mDecorated;

    public TLSChannel(TCPChannel toDecorate)
    {
        mDecorated = toDecorate;
    }

    @Override
    public void receive(byte[] packet)
    {

    }

    @Override
    public void readFinish()
    {

    }

    @Override
    public void close()
    {

    }

    @Override
    public void writeFinish()
    {

    }
}
