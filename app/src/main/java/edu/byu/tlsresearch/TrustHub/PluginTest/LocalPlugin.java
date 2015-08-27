package edu.byu.tlsresearch.TrustHub.PluginTest;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;

/**
 * Created by ben on 8/27/15.
 * Abstract class that facilitates local communication between the PolicyEngine and the plugin.
 */
public abstract class LocalPlugin extends Service implements PluginInterface {

    //Binder to be returned to the LocalPluginHandler
    private final IBinder mBinder = new LocalBinder();

    //Binder providing access to the LocalPlugin
    private class LocalBinder extends Binder
    {
        LocalPlugin getService()
        {
            return LocalPlugin.this;
        }
    }

    @Override
    public IBinder onBind(Intent intent)
    {
        return mBinder;
    }

}
