package edu.byu.tlsresearch.TrustHub.PluginTest;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import java.security.cert.X509Certificate;
import java.util.List;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;
import edu.byu.tlsresearch.TrustHub.Utils.IPCUtils;

/**
 * Created by ben on 8/20/15.
 * Abstract class that implements the plugin API and facilitates communication between the plugin
 * and TrustHub.
 */
public abstract class TrustHubPlugin extends Service implements PluginInterface {

    private static final String TAG = "TrustHubPlugin";     //Log tag

    //Communication codes between TrustHubPluginHandler and TrustHubPlugin for return Messages
    private static final int COMM_OK = 0;           //Communication normal
    private static final int COMM_BAD_DATA = 1;     //Error reading certificates

    //Make a new Messenger in order to access MyHandler
    private final Messenger mMessenger = new Messenger(new MyHandler());

    //Handle messages from TrustHub
    private class MyHandler extends Handler {
        @Override
        public void handleMessage(Message msg)
        {
            switch(msg.what)
            {
                case 1: //Valid message
                    int com_ret; //Return communication code

                    //Extract X.509 Certificates
                    List<X509Certificate> cert_chain = extractCertificates(msg);

                    //If data is bad, set return message accordingly
                    if(cert_chain == null)
                    {
                        com_ret = COMM_BAD_DATA;
                    }
                    else {
                        com_ret = COMM_OK;
                    }
                    //Run the check function
                    PluginInterface.POLICY_RESPONSE response = check(cert_chain);
                    //Return the result
                    reply(msg.replyTo, response, com_ret);
                    break;
                default:    //Should not happen
                    Log.e(TAG, "Invalid message");
                    assert false;
            }
        }
    }

    //Return Binder to TrustHub
    @Override
    public IBinder onBind(Intent intent)
    {
        return mMessenger.getBinder();
    }

    /*
        Extract X.509 Certificates from received message
        @param msg      Received message from TrustHub
        @return         List of X.509 Certificates
     */
    private List<X509Certificate> extractCertificates(Message msg)
    {
        List<X509Certificate> ret;

        try {
            ret = (List<X509Certificate>) IPCUtils.unbundle(msg.getData());
        }
        catch(ClassCastException e)
        {
            Log.e(TAG, "Unable to cast certificates");
            ret =  null;
        }

        return ret;
    }

    /*
        Sends a reply message to TrustHub
        @param replyTo      TrustHub Messenger
        @param res          Result of check function
        @param com_ret      Communication code for connection between this plugin and TrustHub
     */
    private void reply(Messenger replyTo, PluginInterface.POLICY_RESPONSE res, int com_ret)
    {
        //Check that replyTo is not null
        if(replyTo == null)
        {
            Log.e(TAG, "Error: No reply field");
            return;
        }

        //Create message
        Message ret = Message.obtain(null, com_ret, IPCUtils.PolicyResponseToInt(res), 0, null);

        //Send return message
        try {
            replyTo.send(ret);
        }
        catch (RemoteException e)
        {
            Log.e(TAG, "Error running service: RemoteException thrown.", e);
        }
    }
}
