package edu.byu.tlsresearch.TrustHub.Controllers.Channel;

/**
 * Created by sheidbri on 1/15/15.
 */
public interface IChannel
{
    public void receive(byte[] packet);
    public void readFinish();
    public void close();
    public void writeFinish();
}
