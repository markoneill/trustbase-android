package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import android.util.Log;

import java.nio.channels.SelectionKey;
import java.util.HashMap;
import java.util.Map;

import edu.byu.tlsresearch.TrustHub.Controllers.Channel.TCPChannel;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 5/29/15.
 */
public class TrustHub
{
    private static TLSState mStates = new TLSState();
    private static Map<Connection, SSLProxy> mProxies = new HashMap<Connection, SSLProxy>();

    private static SSLProxy getProxy(Connection key)
    {
        if(mProxies.containsKey(key))
        {
            return mProxies.get(key);
        }
        else
        {
            try
            {
                SSLProxy toReturn = new SSLProxy();
                mProxies.put(key, toReturn);
                return toReturn;
            }
            catch (Exception e)
            {
                Log.e("Trusthub", "Unable to proxy connection: " + key.toString());
                mProxies.put(key, null);
                return null;
            }
        }
    }

    public static void proxyOut(byte[] toWrite, SelectionKey key)
    {
        mStates.sending(toWrite, ((TCPChannel) key.attachment()).getmContext());
//        byte[] toReturn = toWrite;
//        if(key.attachment() instanceof TCPChannel)
//        {
//            SSLProxy curProxy = getProxy(((TCPChannel) key.attachment()).getmContext());
//            if(curProxy != null)
//            {
//                try
//                {
//                    curProxy.send(toWrite);
//                }
//                catch(SSLException e)
//                {
//                    Log.e("TrustHub", "SSL Error on: " + ((TCPChannel) key.attachment()).getmContext().toString());
//                    //TODO reset the connection or something here
//                }
//            }
//            else
//            {
//                Log.d("TrustHub", "Proxy does not exists for: " + ((TCPChannel) key.attachment()).getmContext().toString());
//            }
//        }
//        else
//        {
//            Log.d("TrustHub", "NOT TCPWrite");
//        }
//        SocketPoller.getInstance().noProxySend(key, toReturn);
    }

    public static void proxyIn(byte[] packet, SelectionKey key)
    {
        mStates.received(packet, ((TCPChannel) key.attachment()).getmContext());
        //((IChannelListener) key.attachment()).receive(packet);
    }
}
