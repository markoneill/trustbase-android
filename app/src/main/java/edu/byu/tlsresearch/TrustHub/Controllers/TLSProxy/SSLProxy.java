package edu.byu.tlsresearch.TrustHub.Controllers.TLSProxy;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import edu.byu.tlsresearch.TrustHub.Controllers.Socket.IChannelListener;
import edu.byu.tlsresearch.TrustHub.Controllers.Socket.SocketPoller;

/**
 * Created by sheidbr on 7/27/15.
 *
 * Concurrency Notes: There are two concurrency issues to be aware of:
 *
 * The wrap() and unwrap() methods may execute concurrently of each other.
 * The SSL/TLS protocols employ ordered packets. Applications must take care to ensure that generated packets are delivered in sequence. If packets arrive out-of-order, unexpected or fatal results may occur.
 *
 * For example:
 *
 * synchronized (outboundLock) {
 * sslEngine.wrap(src, dst);
 * outboundQueue.put(dst);
 * }
 *
 * As a corollary, two threads must not attempt to call the same method (either wrap() or unwrap()) concurrently, because there is no way to guarantee the eventual packet ordering.
 *
 */
public class SSLProxy
{
    private static SSLContext sslc = null;
    private static String storeFile = "trusthubstore.jks";
    private void setupContext() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException
    {
        if(sslc == null)
        {
            KeyStore ks = KeyStore.getInstance("JKS");
            KeyStore ts = KeyStore.getInstance("JKS");

            char[] passphrase = "password".toCharArray();

            ks.load(new FileInputStream(storeFile), passphrase);
            ts.load(new FileInputStream(storeFile), passphrase);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, passphrase);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);

            sslc = SSLContext.getInstance("TLS");
            sslc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        }
    }

    private SSLEngine clientSideEngine;
    private SSLEngineResult clientResult;
    private ByteBuffer cTos;
    private ByteBuffer toApp;
    private ByteBuffer fromApp;

    private SSLEngine serverSideEngine;
    private SSLEngineResult serverResult;
    private ByteBuffer sToc;
    private ByteBuffer toNetwork;
    private ByteBuffer fromNetwork;

    private SelectionKey mKey;

    public SSLProxy(SelectionKey key) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException
    {
        mKey = key;
        setupContext();

        clientSideEngine = sslc.createSSLEngine();
        clientSideEngine.setUseClientMode(false);
        SSLSession clientSession = clientSideEngine.getSession();
        cTos = ByteBuffer.allocate(clientSession.getApplicationBufferSize());
        toApp = ByteBuffer.allocate(clientSession.getPacketBufferSize() + 50);
        fromApp = ByteBuffer.allocate(clientSession.getPacketBufferSize() + 50);
        clientSideEngine.beginHandshake(); //Force the getHandshakeStatus to be correct

        serverSideEngine = sslc.createSSLEngine();
        serverSideEngine.setUseClientMode(true);
        SSLSession serverSession = serverSideEngine.getSession();
        sToc = ByteBuffer.allocate(clientSession.getApplicationBufferSize());
        toNetwork = ByteBuffer.allocate(clientSession.getPacketBufferSize() + 50);
        fromNetwork = ByteBuffer.allocate(clientSession.getPacketBufferSize() + 50);
        serverSideEngine.beginHandshake(); //Force the getHandshakeStatus to be correct
    }

    public void send(byte[] toSend) throws javax.net.ssl.SSLException
    {
        handle(toSend, toApp, fromApp, clientSideEngine, clientResult,
                cTos, sToc, toNetwork, serverSideEngine, serverResult);
        writeout();
    }

    public void receive(byte[] toSend) throws javax.net.ssl.SSLException
    {
        handle(toSend, toNetwork, fromNetwork, serverSideEngine, serverResult,
                sToc, cTos, toApp, clientSideEngine, clientResult);
        writeout();
    }

    public void writeout()
    {
        toApp.flip();
        toNetwork.flip();
        if(toApp.hasRemaining())
        {
            byte[] toReceive = new byte[toApp.remaining()];
            toApp.get(toReceive);
            ((IChannelListener) mKey.attachment()).receive(toReceive);
        }
        if(toNetwork.hasRemaining())
        {
            byte[] toSend = new byte[toNetwork.remaining()];
            toNetwork.get(toSend);
            SocketPoller.getInstance().noProxySend(mKey, toSend);
        }
        toApp.clear();
        toNetwork.clear();
    }

    public static void handle(byte[] toSend,
                              ByteBuffer toConnection, ByteBuffer fromConnection,
                              SSLEngine connEngine, SSLEngineResult connResult,
                              ByteBuffer toOther, ByteBuffer fromOther, ByteBuffer otherOut,
                              SSLEngine otherEngine, SSLEngineResult otherResult) throws javax.net.ssl.SSLException
    {
        fromConnection.put(toSend); //TODO: Check for room
        fromConnection.flip();
        if(connEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING)
        {
            connEngine.unwrap(fromConnection, toOther); //TODO: check overflow/underflow
            toOther.flip();
            if(otherEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING)
            {
                while(toOther.hasRemaining())
                {
                    otherEngine.wrap(toOther, otherOut);
                }
            }
            toOther.compact();
        }
        else
        {
            do
            {
                switch (connEngine.getHandshakeStatus())
                {
                    case NEED_UNWRAP:
                        connResult = connEngine.unwrap(fromConnection, toOther);
                        runDelegatedTasks(connResult, connEngine);
                        break;
                    case NEED_WRAP:
                        while(connEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP)
                        {
                            connResult = connEngine.wrap(fromConnection, toConnection);
                            runDelegatedTasks(connResult, connEngine);
                        }
                        break;
                }
            } while (connResult.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.FINISHED
                      && (connResult.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_UNWRAP
                            || fromConnection.hasRemaining()));

            //If handshake just finised write out anything in buffer already
            if(connResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED)
            {
                fromOther.flip();
                while(fromOther.hasRemaining())
                {
                    connEngine.wrap(fromOther, toConnection);
                }
                fromOther.clear();
            }
        }
        fromConnection.compact();
    }


    private static void runDelegatedTasks(SSLEngineResult result, SSLEngine engine)
    {

        if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK)
        {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null)
            {
                runnable.run();
            }
            SSLEngineResult.HandshakeStatus hsStatus = engine.getHandshakeStatus();
        }
    }
}
