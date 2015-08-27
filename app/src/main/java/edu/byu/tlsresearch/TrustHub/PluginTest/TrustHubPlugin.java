package edu.byu.tlsresearch.TrustHub.PluginTest;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.util.Log;

import java.security.cert.X509Certificate;
import java.util.List;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;

/**
 * Created by ben on 8/20/15.
 * Abstract class that implements the plugin API and facilitates communication between the plugin and TrustHub.
 * Note: This class may not be necessary in the future.
 */
public abstract class TrustHubPlugin extends Service implements PluginInterface {
    private static final String TAG = "TrustHubPlugin";

    private final Messenger mMessenger = new Messenger(new MyHandler());

    private class MyHandler extends Handler {
        @Override
        public void handleMessage(Message msg)
        {
            long time = msg.getWhen();
            switch(msg.what)
            {
                case 1:
                    //Valid message
                    //Extract X.509 Certificates
                    List<X509Certificate> cert_chain = extractCertificates(msg);
                    //Run the check function
                    PluginInterface.POLICY_RESPONSE response = check(cert_chain);
                    //Return the result
                    reply(response);
                    break;
                default:
                    super.handleMessage(msg);
                    Log.e(TAG, "Invalid message");
            }
        }
    }

    @Override
    public IBinder onBind(Intent intent)
    {
        return mMessenger.getBinder();
    }

    private List<X509Certificate> extractCertificates(Message msg)
    {
        //TODO: Write class
        return null;
    }

    private void reply(PluginInterface.POLICY_RESPONSE res)
    {
        //TODO: Write class
    }
}
