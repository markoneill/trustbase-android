package edu.byu.tlsresearch.TrustHub.PluginTest;

import android.os.IBinder;

import java.security.cert.X509Certificate;
import java.util.List;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;

/**
 * Created by ben on 8/27/15.
 *
 */
public class LocalPluginHandler implements PluginInterface {

    public LocalPluginHandler(LocalPlugin.LocalBinder bin)
    {
        boundPlugin = bin;
    }

    private LocalPlugin.LocalBinder boundPlugin;

    @Override
    public POLICY_RESPONSE check(List<X509Certificate> cert_chain) {
        return boundPlugin.getService().check(cert_chain);
    }
}
