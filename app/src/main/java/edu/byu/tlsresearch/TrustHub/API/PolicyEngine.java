package edu.byu.tlsresearch.TrustHub.API;

import android.util.Log;

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

/**
 * Created by sheidbri on 5/5/15.
 * Handles communication between our service and any bound processes wanting access
 */
public class PolicyEngine
{
    private static PolicyEngine mInstance;
    private ConcurrentLinkedQueue<PluginInterface> mListeners;

    public static PolicyEngine getInstance()
    {
        if (mInstance == null)
        {
            mInstance = new PolicyEngine();
        }
        return mInstance;
    }

    private PolicyEngine()
    {
        mListeners = new ConcurrentLinkedQueue<>();
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
        PluginInterface.POLICY_RESPONSE toReturn = PluginInterface.POLICY_RESPONSE.VALID_PROXY; //TODO: Valid because we just let the default CA system take a look
        while (iterator.hasNext())
        {
            myTask task = new myTask((PluginInterface) iterator.next(), cert_chain);
            Future<PluginInterface.POLICY_RESPONSE> future = executor.submit(task);
            try
            {
                toReturn = future.get(timeout, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e)
            {
            } catch (ExecutionException e)
            {
            } catch (TimeoutException e)
            {
                Log.d("PolicyEngine", "timeout");
            }
        }
        executor.shutdown();
        return toReturn;
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
