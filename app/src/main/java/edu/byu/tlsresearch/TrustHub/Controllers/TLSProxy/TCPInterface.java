package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 4/30/15.
 */
public interface TCPInterface
{
    public byte[] received(byte[] packet, Connection context);
    public byte[] sending(byte[] packet, Connection context);
}
