package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 5/29/15.
 */
public class TrustHub
{
    private static TLSState mStates = new TLSState();
    public static byte[] proxyOut(byte[] toWrite, Connection connection)
    {
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
