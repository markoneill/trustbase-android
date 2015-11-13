package edu.byu.tlsresearch.TrustHub.API;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.util.Log;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Created by sheidbri on 5/5/15.
 * Handles communication between our service and any bound processes wanting access
 */
public class PolicyEngine extends Service
{
    private static PolicyEngine mInstance;
    private ConcurrentLinkedQueue<PluginInterface> mListeners;
    private final IBinder mBinder = new PluginBinder();
    private static String TAG = "PolicyEngine";

    //onStartCommand is probably not necessary; moved functionality to onBind.
    /*@Override
    public int onStartCommand(Intent intent, int flags, int startId)
    {
        mListeners = new ConcurrentLinkedQueue<PluginInterface>();
        mInstance = this;
        return START_STICKY;
    }*/

    public class PluginBinder extends Binder
    {
        public void addPlugin(PluginInterface toAdd)
        {
            PolicyEngine.getInstance().addPlugin(toAdd);
        }
    }

    public static PolicyEngine getInstance()
    {
        if (mInstance == null)
        {
            mInstance = new PolicyEngine();
        }
        return mInstance;
    }

    @Override
    public IBinder onBind(Intent intent)
    {
        Log.d(TAG, "Queried");
        mListeners = new ConcurrentLinkedQueue<PluginInterface>();
        mInstance = this;
        return mBinder;
    }

    public void addPlugin(PluginInterface l)
    {
        mListeners.add(l);
    }

    public PluginInterface.POLICY_RESPONSE policy_check(List<X509Certificate> cert_chain)
    {
        return toListeners(cert_chain);
    }

    private PluginInterface.POLICY_RESPONSE toListeners(List<X509Certificate> cert_chain)
    {
        ExecutorService executor = Executors.newCachedThreadPool();
        final Iterator iterator = mListeners.iterator();
        int timeout = 6000;
        PluginInterface.POLICY_RESPONSE toReturn = PluginInterface.POLICY_RESPONSE.VALID; //TODO: Valid because we just let the default CA system take a look
        //Set congress parameters.
        double congress_threshold = 0.5;
        int num_plugins = 0;
        int plugin_sum = 0;

        while (iterator.hasNext())
        {
            num_plugins++;
            myTask task = new myTask((PluginInterface) iterator.next(), cert_chain);
            Future<PluginInterface.POLICY_RESPONSE> future = executor.submit(task);
            try
            {
                //Put decision making logic here
                //If there are no plugins, return VALID
                PluginInterface.POLICY_RESPONSE pluginResult;
                pluginResult = future.get(timeout, TimeUnit.MILLISECONDS);
                //Increment sum if response is valid
                if(pluginResult == PluginInterface.POLICY_RESPONSE.VALID)
                    plugin_sum++;
            }
            catch (InterruptedException e)
            {
            }
            catch (ExecutionException e)
            {
            }
            catch (TimeoutException e)
            {
                Log.d("PolicyEngine", "timeout");
            }
        }
        executor.shutdown();
        //Calculate response based on plugin responses
        double congress_rate = (double) plugin_sum / (double) num_plugins;
        //Check that the agreeance rate between the plugins is greater than or equal to the threshold
        if((congress_rate - congress_threshold) > -0.001) {
            //Check for CA validation
            if(check_CA(cert_chain)) {
                //Log.d(TAG, "Returning VALID");
                toReturn = PluginInterface.POLICY_RESPONSE.VALID;
            }
            else {
                //Log.d(TAG, "Returning VALID_PROXY");
                toReturn = PluginInterface.POLICY_RESPONSE.VALID_PROXY;
            }
        }
        else {
            //Log.d(TAG, "Returning INVALID");
            toReturn = PluginInterface.POLICY_RESPONSE.INVALID;
        }
        return PluginInterface.POLICY_RESPONSE.VALID;//toReturn;
    }

    /*
        Checks a certificate chain against the root CA system
        @param cert_chain       Chain of certificates to be checked
        @return         true if the cert_chain is trusted, false if not
     */
    private boolean check_CA(List<X509Certificate> cert_chain)
    {
        boolean result = false;
        try {
            //Create the TrustManagerFactory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore ks = null; //Create the KeyStore.  I'm don't know why we use a value of null
            tmf.init(ks);   //Init TrustManagerFactory using root store
            TrustManager[] tm = tmf.getTrustManagers(); //Extract TrustManagers
            X509TrustManager xtm = (X509TrustManager) tm[0];    //I don't know why it's index 0
            X509Certificate[] cert_arr = new X509Certificate[cert_chain.size()];    //Create cert array
            cert_chain.toArray(cert_arr);   //Populate cert array
            xtm.checkClientTrusted(cert_arr, "RSA");    //Validate cert_chain
            //Log.d(TAG, "Successfully authenticated certificate chain");
            result = true;  //Cert Chain valid.  Return true
        }
        catch(NoSuchAlgorithmException e) {Log.e(TAG, "Algorithm Exception");}
        catch(KeyStoreException e) {Log.e(TAG, "KeyStore Exception");}
        catch(CertificateException e) {
            //cert_chain invalid or is unable to validate.  Return false
            //Log.d(TAG, "Certificate Exception/Untrusted certificates");
            result = false;
        }
        return result;
    }

    private class myTask implements Callable<PluginInterface.POLICY_RESPONSE>
    {
        private List<X509Certificate> mCert_chain;
        private PluginInterface mListener;

        public myTask(PluginInterface l, List<X509Certificate> cert_chain)
        {
            mCert_chain = cert_chain;
            mListener = l;
        }

        @Override
        public PluginInterface.POLICY_RESPONSE call() throws Exception
        {
            return mListener.check(mCert_chain);
        }
    }
}
