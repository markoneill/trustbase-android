package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import android.util.Log;

import java.util.List;
import java.util.ArrayList;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;

import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 5/29/15.
 */
public class TrustHub
{
    /**
     * ClientDecryptEngine (CDE)
     * App --(ClientHello)--> CDE
     * App <--(ServerHello)-- CDE
     * ...
     *
     *
     *
     *     (mitm cert)     unwrap()         (plaintext)         wrap()         (domain Cert)
     * APP -----------> ClientEngine --------------> ServerEngine ---------------> Internet
     *
     *     (mitm cert)     unwrap()         (plaintext)         wrap()         (domain Cert)
     * APP -----------> ClientEngine --------------> ServerEngine ---------------> Internet
     *
     */
    private static TLSState mStates = new TLSState();
    private static List<SSLProxy> mProxies = new ArrayList<SSLProxy>();
    public static byte[] proxyOut(byte[] toWrite, Connection connection)
    {
        Log.d("TrustHub", "Out");
        mStates.sending(toWrite, connection);
        switch (mStates.getState(connection).MitM)
        {
            case PROXY:
                break;
            case NOPROXY:
                break;
            case CHECKCERT:
                break;
            case UNKNOWN:
                break;
        }
        return toWrite;
    }

    public static byte[] proxyIn(byte[] toRead, Connection connection)
    {
        mStates.received(toRead, connection);
        switch (mStates.getState(connection).MitM)
        {
            case PROXY:
                break;
            case NOPROXY:
                break;
            case CHECKCERT:
                break;
            case UNKNOWN:
                break;
        }
        return toRead;
    }
}
