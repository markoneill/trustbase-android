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
import java.util.concurrent.SynchronousQueue;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;
import edu.byu.tlsresearch.TrustHub.Utils.IPCUtils;

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
    private SynchronousQueue<POLICY_RESPONSE> result;

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
                        Log.d(TAG, "Response received: " + msg.arg1);
                        boolean result_result;
                        result_result = result.offer(resp);
                        if(!result_result)
                            Log.e(TAG, "Result not offered");
                        setResult(resp);    //Set data so that check function returns
                    }
                    catch(ClassCastException e) //Throw error if msg has invalid POLICY_RESPONSE
                    {
                        Log.e(TAG, "Invalid response: Bad POLICY_RESPONSE");
                        result.add(null);
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

    /**
        Constructor.
        @param b_service    IBinder of the remote bound plugin
     */
    public TrustHubPluginHandler(IBinder b_service)
    {
        mRequest = new Messenger(b_service);
    }

    /*
     * This function tells the remote plugin to run the check(List<X509Certificate>) command and
     * returns the response to the policy engine.  Currently, this involves serializing the list of
     * certificates to a byte array, putting that byte array into a bundle and sending it to the
     * remote service.  This works for now, but X509Certificates don't implement Serializable in
     * Android (although they do implement it in other Java implementations).  If this breaks in the
     * future, that is probably why.
     * Possible alternative: Write certificates to a shared file and sent file's URI to plugin.
     */
    @Override
    public POLICY_RESPONSE check(List<X509Certificate> cert_chain) {
        if(mRequest != null)
        {
            Message req = Message.obtain(null, CHECK_CERTIFICATES);   //Send a certificate check message
            Bundle bd = IPCUtils.bundle(cert_chain);    /*Convert certificates in to a bundle.
                                                          This method appears to work but is not
                                                          openly supported.*/
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

            POLICY_RESPONSE p = result.poll();

            Log.d(TAG, "Result passed through queue: " + IPCUtils.PolicyResponseToInt(p));

            return p;

//            //TODO: Put timeout in this plugin or in Policy Engine?
//            //Start timeout counter.  This functionality may be moved to the Policy Engine
//            long start_time = System.currentTimeMillis();
//
//            //Log.d(TAG, "Entering response loop");
//
//            //Wait for the Response Handler to respond or 5 seconds
//            while(System.currentTimeMillis() < start_time + 5000)
//            {
//                if(check_result != null)
//                {
//                    //Log.d(TAG, "Response received by loop");
//                    POLICY_RESPONSE result = check_result;
//                    resetResult();
//                    return result;
//                }
//            }
//
//            Log.d(TAG, "Loop timed out");
//            return null;
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
