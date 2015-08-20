package edu.byu.tlsresearch.TrustHub.PluginTest.Resources.TwoWayCom;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.support.v7.app.ActionBarActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;

import java.util.ArrayList;


public class TwoWayActivity extends ActionBarActivity {

    private static final String TAG="Main";

    private Messenger mOutgoing = null;
    private Messenger mIncoming = new Messenger(new IncomingHandler());

//    private TestStructure ts;
    private ArrayList<String> ls;

    private class IncomingHandler extends Handler{
        @Override
        public void handleMessage(Message msg)
        {
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

    @Override
    protected void onStart()
    {
        super.onStart();
        //Bind to service
        Intent i = new Intent();
        i.setClassName("com.example.ben.twowaycomservice",
                "com.example.ben.twowaycomservice.TwoWayService");
        if(i.resolveActivity(getPackageManager()) != null) {
            Log.d(TAG, "Remote Intent Resolved");
            bindService(i, mConnection, Context.BIND_AUTO_CREATE);
        }
        else {
            Log.e(TAG, "Remote Intent not Resolved");
        }
        initStructure();
    }

    @Override protected void onStop()
    {
        super.onStop();
        if(mOutgoing != null)
            unbindService(mConnection);
    }

    private ServiceConnection mConnection = new ServiceConnection()
    {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            mOutgoing = new Messenger(service);
            Log.i(TAG, "Service Connected");
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            mOutgoing = null;
            Log.e(TAG, "Error: Service unexpectedly disconnected");
        }
    };

    public void run_com(View v)
    {
        Log.d(TAG, "Start Button clicked");
        if(mOutgoing != null)
        {
            Message msg = Message.obtain(null, 1, 0, 0);
            msg.replyTo = mIncoming;
//            Bundle data = IPCUtils.bundle(ts);
            Bundle data = IPCUtils.bundle(ls);
            msg.setData(data);
            try {
                mOutgoing.send(msg);
                Log.d(TAG, "Message time: " + msg.getWhen());
            }
            catch(RemoteException e)
            {
                Log.e(TAG, "Error running service: RemoteException thrown.", e);
            }
            ArrayList<String> der = (ArrayList<String>) IPCUtils.unbundle(msg.getData());
            if(der != null) {
                Log.d(TAG, "Attempted retrieval of test data: " + der.toString());
            }
            else
                Log.e(TAG, "Could not unbundle test data.");
        }
    }

    private void initStructure()
    {
//        ts = new TestStructure();
//        ts.setName("test");
//        TreeMap<Integer, Student> dats = new TreeMap<>();
//        dats.put(1, new Student("Mary", "Lou"));
//        dats.put(0, new Student("Mark", "Hammel"));
//        dats.put(4576, new Student("Bubba", "Bubba"));
//        ts.setNotParcelable(dats);
//
//        Log.i(TAG, "Data: " + ts.toString());

        ls = new ArrayList<>();
        ls.add("Mary");
        ls.add("Mark");
        ls.add("Bubba");

        Log.i(TAG, "Data: " + ls.toString());

    }
}
