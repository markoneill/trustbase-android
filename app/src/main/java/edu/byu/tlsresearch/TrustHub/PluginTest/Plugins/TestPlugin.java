package edu.byu.tlsresearch.TrustHub.PluginTest.Plugins;

import android.util.Log;

import java.security.cert.X509Certificate;
import java.util.List;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;

/**
 * Created by ben on 8/31/15.
 */
public class TestPlugin implements PluginInterface {

    private static final String TAG = "TestPlugin";

    @Override
    public POLICY_RESPONSE check(List<X509Certificate> cert_chain) {

        //Log.d(TAG, "Success!");

        /*X509Certificate cert = null;
        if(cert_chain != null) {
            cert = cert_chain.get(0);
            Log.d(TAG, "Certificate: " + cert.toString());
        }
        else {
            Log.d(TAG, "No certificates");
        }*/

        return POLICY_RESPONSE.VALID;
    }
}
