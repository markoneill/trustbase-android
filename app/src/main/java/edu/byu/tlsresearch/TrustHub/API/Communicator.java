package edu.byu.tlsresearch.TrustHub.API;

import android.util.Log;

import java.util.Iterator;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy.TCPInterface;
import edu.byu.tlsresearch.TrustHub.model.Connection;

/**
 * Created by sheidbri on 5/5/15.
 * Handles communication between our service and any bound processes wanting access
 */
public class Communicator
{
    private static Communicator mInstance;
    private ConcurrentLinkedQueue<TCPInterface> Listeners;

    public static Communicator getInstance()
    {
        if (mInstance == null)
        {
            mInstance = new Communicator();
        }
        return mInstance;
    }

    private Communicator()
    {
        Listeners = new ConcurrentLinkedQueue<>();
    }

    public void addListener(TCPInterface l)
    {
        Listeners.add(l);
    }

    public byte[] sendTCPbody(byte[] payload, Connection context)
    {
        return toListeners(payload, callType.SEND, context);
    }

    public byte[] receiveTCPbody(byte[] payload, Connection context)
    {
        return toListeners(payload, callType.RECEIVE, context);
    }

    private byte[] toListeners (byte[] payload, callType t, Connection context)
    {
        ExecutorService executor = Executors.newCachedThreadPool();
        final Iterator iterator = Listeners.iterator();
        int timeout = 6000;
        while (iterator.hasNext())
        {
            myTask task = new myTask((TCPInterface) iterator.next(), payload, t, context);
            Future<byte[]> future = executor.submit(task);
            try
            {
                payload = future.get(timeout, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e)
            {
                continue;
            } catch (ExecutionException e)
            {
                continue;
            } catch (TimeoutException e)
            {
                Log.d("Communicator", "timeout");
                continue;
            }
        }
        executor.shutdown();
        return payload;
    }

    private enum callType
    {
        SEND, RECEIVE;
    }


    private class myTask implements Callable<byte[]>
    {
        private byte[] mToReturn;
        private TCPInterface mListener;
        private callType mType;
        private Connection mContext;
        public myTask(TCPInterface l, byte[] payload, callType t, Connection context)
        {
            mListener = l;
            mToReturn = payload;
            mType = t;
            mContext = context;
        }
        @Override
        public byte[] call() throws Exception
        {
            switch (mType)
            {
                case SEND:
                    return mListener.sending(mToReturn, mContext);
                case RECEIVE:
                    return mListener.received(mToReturn, mContext);
            }
            return mToReturn;
        }
    }
}
