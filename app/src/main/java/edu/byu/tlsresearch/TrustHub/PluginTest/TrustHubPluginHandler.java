package edu.byu.tlsresearch.TrustHub.PluginTest;

import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import java.security.cert.X509Certificate;
import java.util.List;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;
import edu.byu.tlsresearch.TrustHub.PluginTest.Resources.TwoWayCom.IPCUtils;

/**
 * Created by ben on 9/11/15.
 *
 * Handler that connects to a remote TrustHubPlugin.
 */
public class TrustHubPluginHandler implements PluginInterface {

    private static final String TAG = "TrustHubPluginHandler";  //Logging tag

    //Communication codes to specify what the bound plugin should do with messages
    private static final int CHECK_CERTIFICATES = 1;

    private Messenger mRequest = null;
    private Messenger mResponse = new Messenger(new ResponseHandler());
    private POLICY_RESPONSE check_result = null;    //Holds return value received from bound plugin.

    //Handles responses from bound TrustHubPlugin
    private class ResponseHandler extends Handler {
        @Override
        public void handleMessage(Message msg)
        {
            Log.i(TAG, "Response received");
            switch(msg.what)
            {
                case 0:     //Communication OK
                    try {
                        POLICY_RESPONSE resp = IPCUtils.IntToPolicyResponse(msg.arg1);   //Cast returned data
                        setResult(resp);    //Set data so that check function returns
                    }
                    catch(ClassCastException e) //Throw error if msg has invalid POLICY_RESPONSE
                    {
                        Log.e(TAG, "Invalid response: Bad POLICY_RESPONSE");
                        resetResult();  //Make the Policy Engine time out.  This functionality may be changed in the future.
                    }
                    break;
                case 1:     //Communication error
                    Log.e(TAG, "Communication error with bound plugin");
                    resetResult();  //Make the Policy Engine time out.  This functionality may be changed in the future.
                    break;
                default:    //Invalid "what."  Should not happen
                    Log.e(TAG, "Invalid response: Invalid communication code");
                    assert false;
            }
        }
    }

    /*
        Constructor.
        @param b_service    IBinder of the remote bound plugin
     */
    public TrustHubPluginHandler(IBinder b_service)
    {
        mRequest = new Messenger(b_service);
    }

    @Override
    public POLICY_RESPONSE check(List<X509Certificate> cert_chain) {
        /*
            TODO: Re-figure out how to send an X509Certificate to a remote process
            Possible solution: Write certificates to a shared file and send URIs to plugins
         */
        if(mRequest != null)
        {
            Message req = Message.obtain(null, CHECK_CERTIFICATES);   //Send a certificate check message
            Bundle bd = IPCUtils.bundle(cert_chain);    //WHAAAAT!??  That's supposed to be Serializable.  This may have to be done differently.
            req.setData(bd);    //Attach certificates to the request message
            req.replyTo = mResponse;    //Attach response messenger

            //Send the request
            try {
                mRequest.send(req);
            }
            catch(RemoteException e)
            {
                Log.e(TAG, "Error sending check certificate request");
            }

            //TODO: Put timeout in this plugin or in Policy Engine?
            //Start timeout counter.  This functionality may be moved to the Policy Engine
            long start_time = System.currentTimeMillis();

            Log.d(TAG, "Entering response loop");

            //Wait for the Response Handler to respond or 5 seconds
            while(System.currentTimeMillis() < start_time + 5000)
            {
                if(check_result != null)
                {
                    Log.d(TAG, "Response received by loop");
                    POLICY_RESPONSE result = check_result;
                    resetResult();
                    return result;
                }
            }

            Log.d(TAG, "Loop timed out");
            return null;
        }
        else {
            //Plugin not bound return null
            Log.d(TAG, "Remote plugin not bound");
            return null;
        }
    }

    private void setResult(POLICY_RESPONSE new_result)
    {
        check_result = new_result;
    }

    private void resetResult()
    {
        check_result = null;
    }

}
