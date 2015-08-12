package edu.byu.tlsresearch.TrustHub.Controllers.Channel;

/**
 * Created by sheidbri on 1/15/15.
 */
public interface IChannel
{
    void receive(byte[] packet);
    void readFinish();
    void close();
    void writeFinish();
}
