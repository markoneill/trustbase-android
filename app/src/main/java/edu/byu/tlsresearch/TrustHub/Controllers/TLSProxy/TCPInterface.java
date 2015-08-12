package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 4/30/15.
 */
public interface TCPInterface
{
    byte[] received(byte[] packet, Connection context);
    byte[] sending(byte[] packet, Connection context);
}
