package edu.byu.tlsresearch.TrustHub.Controllers.FromApp;

import android.content.Intent;
import android.net.VpnService;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import org.apache.http.conn.util.InetAddressUtils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;

import edu.byu.tlsresearch.TrustHub.API.Communicator;
import edu.byu.tlsresearch.TrustHub.Controllers.IPLayer.IPController;
import edu.byu.tlsresearch.TrustHub.Controllers.Socket.SocketPoller;
import edu.byu.tlsresearch.TrustHub.API.PluginInterface;
import edu.byu.tlsresearch.TrustHub.model.IPaddr;

/**
 * Handles the VPNService
 * Marshalls traffic between non-protected sockets and the IPController
 * Handles Bind requests that get sent to the Communicator
 */

public class VPNServiceHandler extends VpnService implements Runnable
{
    private Thread mInterfaceThread;
    private Thread mPollerThread;
    private ParcelFileDescriptor mInterface;
    private FileOutputStream mAppOut;

    private static VPNServiceHandler mInstance = null;
    public static String TAG = "VPNServiceHandler";

    private final IBinder mBinder = new PluginBinder();

    public static void setVPNService(VPNServiceHandler toSet)
    {
        mInstance = toSet;
    }

    public static VPNServiceHandler getVPNServiceHandler()
    {
        return mInstance;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId)
    {
        // Stop any previous session
        if (mInterfaceThread != null)
        {
            mInterfaceThread.interrupt();
        }

        // Start a new session
        mInterfaceThread = new Thread(this, TAG);
        mPollerThread = new Thread(SocketPoller.getInstance(), TAG);
        VPNServiceHandler.setVPNService(this);
        mInterfaceThread.start();
        mPollerThread.start();

        // http://developer.android.com/reference/android/app/Service.html
        // For started services, there are two additional major modes of
        // operation
        // they can decide to run in, depending on the value they return from
        // onStartCommand(): START_STICKY is used for services that are
        // explicitly
        // started and stopped as needed, while START_NOT_STICKY or
        // START_REDELIVER_INTENT are used for services that should only remain
        // running while processing any commands sent to them. See the linked
        // documentation for more detail on the semantics.

        return START_STICKY;
    }

    public void addPlugin(PluginInterface callback)
    {
        Communicator.getInstance().addPlugin(callback);
    }

    public class PluginBinder extends Binder
    {
        public VPNServiceHandler getService()
        {
            return VPNServiceHandler.getVPNServiceHandler();
        }
    }

    @Override
    public IBinder onBind(Intent intent)
    {
        if (mInterfaceThread == null || mPollerThread == null) // Must (my requirement?) call through onStartCommand because I think that is the only way to have it prepared
        {
            //TODO: can we just call onStartCommand
            return null;
        }
        return mBinder;
    }

    public boolean receive(byte[] packet)
    {
        boolean success = false;
        try
        {
            mAppOut.write(packet);  //TODO: Test whether receive and reads at the same time crash it
            mAppOut.flush();
            success = true;
        } catch (IOException e)
        {
            Log.d(TAG, "App Exception" + e);
            e.printStackTrace();
        }
        return success;
    }

    @Override
    public void run()
    {
        Log.d(TAG, "Setting up Tunnel and Connections to outside");
        configure();
        if (mInterface == null)
        {
            Log.e(TAG, "App not prepared?");
            return; //TODO: re-prepare the app?
        }
        FileInputStream mAppIn = new FileInputStream(mInterface.getFileDescriptor());
        mAppOut = new FileOutputStream(mInterface.getFileDescriptor());

        ByteBuffer packet = ByteBuffer.allocate(32767);
        int length = 0;

        while (true)
        {
            packet.clear();
            try
            {
                length = mAppIn.read(packet.array());
            } catch (IOException e)
            {
                Log.e(TAG, "Error reading from interface");
            }

            if (length > 0)
            {
                packet.limit(length);
                byte[] toPacket = new byte[packet.limit()];
                packet.get(toPacket);
                IPController.send(toPacket);
            }
            // TODO: don't want busy loop
        }
    }

    /**
     * Configure the "VPN"
     */
    private void configure()
    {
        Builder builder = new Builder();
        IPaddr ip = getIPAddress(true);
        if (ip == null)
        {
            Log.e(TAG, "Network not detected");
            return;
        }
        Log.d(TAG, "IP ADDRESS IS: " + ip.toString() + "/" + ip.getMask());
        builder.addAddress(ip.toString(), ip.getMask());
        builder.addRoute("0.0.0.0", 0);
        // builder.addDnsServer("8.8.8.8"); // TODO get current DNS Servers?

        // API 21
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
        {
            builder.allowFamily(10); //Should be == AF_INET6 allowing ipv6 to bypass this
            builder.setBlocking(true);
        }

        closeTun();
        mInterface = builder.establish();
        if (mInterface == null)
        {
            Log.e(TAG, "Application not prepared for VPNService");
        }
    }

    private static IPaddr getIPAddress(boolean useIPv4)
    {
        // WifiManager wm = (WifiManager) getSystemService(WIFI_SERVICE);
        // String ip = Formatter.formatIpAddress(wm.getConnectionInfo().getIpAddress());
        IPaddr toReturn = new IPaddr();
        try
        {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (int i = 0; i < interfaces.size(); i++)
            {
                List<InetAddress> addrs = Collections.list(interfaces.get(i).getInetAddresses());
                for (int k = 0; k < addrs.size(); k++)
                {
                    toReturn.setMask(interfaces.get(i).getInterfaceAddresses().get(k).getNetworkPrefixLength());
                    if (!addrs.get(k).isLoopbackAddress())
                    {
                        toReturn.setAddress(addrs.get(k).getHostAddress().toUpperCase());
                        boolean isIPv4 = InetAddressUtils.isIPv4Address(addrs.get(k).getHostAddress().toUpperCase());
                        if (useIPv4)
                        {
                            if (isIPv4)
                                return toReturn;
                        } else
                        {
                            return null;
                        }
                    }
                }
            }
        } catch (Exception ex)
        {
            Log.d(TAG, "VPNIPException: " + ex);
        } // for now eat exceptions
        return null;
    }

    @Override
    public void onDestroy()
    {
        end();
    }

    @Override
    public void onRevoke()
    {
        end();
    }

    private void end()
    {
        if (mInterfaceThread != null)
        {
            mInterfaceThread.interrupt(); //stop the thread
        }
        if (mPollerThread != null)
        {
            mPollerThread.interrupt();
        }
        this.stopSelf(); //stop the VPNService
        closeTun();
    }

    private void closeTun()
    {
        if (mInterface != null)
        {
            try
            {
                mInterface.close();
            } catch (IOException e)
            {
                Log.e(TAG, "Error closing interface: " + e);
            }
        }
    }
}

/*
 * 
 * // Remove strict mode (Not sure if necessary) if
 * (android.os.Build.VERSION.SDK_INT > 9) { StrictMode.ThreadPolicy policy = new
 * StrictMode.ThreadPolicy.Builder() .permitAll().build();
 * StrictMode.setThreadPolicy(policy); }
 */
