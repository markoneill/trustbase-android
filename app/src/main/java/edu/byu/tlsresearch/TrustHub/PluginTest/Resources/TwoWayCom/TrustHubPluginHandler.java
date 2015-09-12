package edu.byu.tlsresearch.TrustHub.PluginTest.Resources.TwoWayCom;

import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.util.Log;

import java.security.cert.X509Certificate;
import java.util.List;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;

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

    //Handles responses from bound TrustHubPlugin
    private class ResponseHandler extends Handler {
        @Override
        public void handleMessage(Message msg)
        {
            //TODO: Rewrite to handle TrustHub traffic
            Log.i(TAG, "Reply received");
            switch(msg.what)
            {
                case 0:
                    Log.d(TAG, "Time was even"); break;
                case 1:
                    Log.d(TAG, "Time was odd"); break;
                default:
                    Log.e(TAG, "Invalid message");
            }
        }
    }

    /*
        Constructor.
     */
    TrustHubPluginHandler(IBinder b_service)
    {
        mRequest = new Messenger(b_service);
    }

    @Override
    public POLICY_RESPONSE check(List<X509Certificate> cert_chain) {
        //TODO: Figure out how to have this send a request and then receive a response
        return null;
    }

    /*
        TODO
        Write methods:
        send(Bundle data, int com_code)

     */
}
