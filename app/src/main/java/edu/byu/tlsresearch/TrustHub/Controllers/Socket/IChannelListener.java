package edu.byu.tlsresearch.TrustHub.Controllers.Socket;

/**
 * Created by sheidbri on 1/15/15.
 */
public interface IChannelListener
{
    public void receive(byte[] packet);
    public void readFinish();
    public void close();
    public void writeFinish();
}
