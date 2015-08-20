package edu.byu.tlsresearch.TrustHub.PluginTest.Resources.TwoWayCom;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import java.util.ArrayList;

public class TwoWayService extends Service {

    private static final String TAG="TwoWayService";
    private final Messenger MyMessenger = new Messenger(new MyHandler());

    public TwoWayService() {
    }

    private class MyHandler extends Handler {
        @Override
        public void handleMessage(Message msg)
        {
            long time = msg.getWhen();
            switch(msg.what)
            {
                case 1:
                    run(time); extract(msg); break;
                default:
                    super.handleMessage(msg);
                    Log.e(TAG, "Invalid message");
            }
            reply(msg, time);
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        Log.d(TAG, "TwoWayService bound");
        return MyMessenger.getBinder();
    }

    public void run(long time)
    {
        Log.i(TAG, "Message received");
        Log.d(TAG, "Message time: " + time);
    }

    public void extract(Message msg)
    {
        ArrayList<String> data = (ArrayList<String>) IPCUtils.unbundle(msg.getData());
        if(data == null)
        {
            Log.e(TAG, "Data not received");
            return;
        }

        Log.d(TAG, "Data: " + data.toString());
    }

    public void reply(Message msg, long time)
    {
        Log.i(TAG, "Replying to message");
        if(msg.replyTo == null)
        {
            Log.e(TAG, "Error: No reply field");
            return;
        }

        int type = (int) (time % 2);
        Message ret = Message.obtain(null, type, 0, 0);
        try {
            msg.replyTo.send(ret);
            Log.d(TAG, "Message returned! Type: " + type);
        }
        catch (RemoteException e)
        {
            Log.e(TAG, "Error running service: RemoteException thrown.", e);
        }
    }
}
