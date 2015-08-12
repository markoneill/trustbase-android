package edu.byu.tlsresearch.TrustHub.Controllers.Socket;

/**
 * Created by sheidbri on 1/15/15.
 */
public interface IChannelListener
{
    void receive(byte[] packet);
    void readFinish();
    void close();
    void writeFinish();
}
