package edu.byu.tlsresearch.TrustHub.PluginTest;

/**
    This service is in charge of holding TrustHub plugins for the PolicyEngine.
    The main functionality of the PluginManager is to bind to remote TrustHub plugins and pass the
    resulting binder to the PolicyEngine.
 A list of local plugins implemented as Java classes are held here.

 */

import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import edu.byu.tlsresearch.TrustHub.API.PolicyEngine;
import edu.byu.tlsresearch.TrustHub.PluginTest.Plugins.TestPlugin;
import edu.byu.tlsresearch.TrustHub.PluginTest.Plugins.WhitelistPlugin;

public class PluginManager extends Service {

    private static final String TAG = "PluginManager";
    private static final String ACTION_TRUSTHUB_PLUGIN = "trusthub.intent.action.plugin";

    public PluginManager() {}

    private PolicyEngine.PluginBinder mPolicyEngineBinder = null;
    private ServiceConnection mPolicyEngineConnection = new ServiceConnection() {

        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            mPolicyEngineBinder = (PolicyEngine.PluginBinder) service;
            Log.d(TAG, "PolicyEngine connected");
            //Wait for binding return call before adding plugins
            mPolicyEngineBinder.addPlugin(mWhitelistPlugin);
            mPolicyEngineBinder.addPlugin(mTestPlugin);
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            mPolicyEngineBinder = null;
            Log.e(TAG, "Lost connection with PolicyEngine");
        }
    } ;

    //Plugin Test
    TestPlugin mTestPlugin = new TestPlugin();
    WhitelistPlugin mWhitelistPlugin = new WhitelistPlugin(this);
    TrustHubPluginHandler mTestRemotePlugin = null;
    private ServiceConnection mRemoteTestPluginConnection = new ServiceConnection() {

        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            mTestRemotePlugin = new TrustHubPluginHandler(service);
            Log.d(TAG, "Remote plugin connected");
            if(mPolicyEngineBinder != null)
                mPolicyEngineBinder.addPlugin(mTestRemotePlugin);
            else
                Log.e(TAG, "Could not add remote plugin to listeners");
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            mTestRemotePlugin = null;
            Log.e(TAG, "Lost connection with Remote Plugin");
        }
    };

    @Override
    public int onStartCommand(Intent intent, int flags, int startId)
    {
        Log.d(TAG, "Successfully started PluginManager");
        //Bind to PolicyEngine
        Log.d(TAG, PolicyEngine.getInstance().toString());
        bindService(new Intent(this.getBaseContext(), PolicyEngine.class), mPolicyEngineConnection,
                Context.BIND_AUTO_CREATE);

        //Bind to plugins
//        Intent iBound = new Intent();
//        iBound.setClassName("com.example.ben.remotetrusthubplugintest",
//                "com.example.ben.remotetrusthubplugintest.TestRemoteTrustHubPlugin");
//        Boolean fBound = bindService(iBound, mRemoteTestPluginConnection, Context.BIND_AUTO_CREATE);
//        Log.d(TAG, "fBound = " + fBound);
//        Log.i(TAG, "Sent binding calls to plugins");
        //Register package broadcast receiver
            //TODO: Do this later
        //Bind to plugins

        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;    //Binding not used
    }

    /*
        Creates a list of package and service names of all TrustHub plugins on the system
     */


    Map<String,String> findPlugins()
    {
        TreeMap<String,String> cur_plugins = new TreeMap<>();   //Current list of plugins

        //Generate intent
        //Query package manager
        //Sort through resolve info

        return cur_plugins;
    }

    /*
        Binds to the plugins
     */
    private void bindPlugins()
    {

    }
}
