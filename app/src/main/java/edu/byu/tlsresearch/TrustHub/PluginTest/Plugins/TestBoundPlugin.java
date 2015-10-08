package edu.byu.tlsresearch.TrustHub.PluginTest.Plugins;

import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import java.security.cert.X509Certificate;
import java.util.List;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;
import edu.byu.tlsresearch.TrustHub.PluginTest.LocalPlugin;

/**
 * Created by ben on 9/9/15.
 * Simple test of a local bound plugin.
 */
public class TestBoundPlugin extends LocalPlugin {

    private static final String TAG = "TestBoundPlugin";

    @Override
    public POLICY_RESPONSE check(List<X509Certificate> cert_chain) {
        Log.d(TAG, "I got it.");
        return POLICY_RESPONSE.VALID;
    }

    @Override
    public IBinder onBind(Intent intent)
    {
        Log.d(TAG, "Binding to TestBoundPlugin");
        return super.onBind(intent);
    }
}
