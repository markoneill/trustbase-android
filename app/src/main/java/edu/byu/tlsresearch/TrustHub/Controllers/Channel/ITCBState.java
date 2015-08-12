package edu.byu.tlsresearch.TrustHub.Controllers.Channel;

/**
 * Created by sheidbri on 1/15/15.
 */
public interface ITCBState
{
    /**
     * @param context
     * @param transport byte[] with TCPHeaders being the start 20+ bytes
     */
    void send(TCPChannel context, byte[] transport);
}
