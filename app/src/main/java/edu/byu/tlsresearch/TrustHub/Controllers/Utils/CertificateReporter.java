package edu.byu.tlsresearch.TrustHub.Controllers.Utils;

import android.util.Base64;
import android.util.Log;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import edu.byu.tlsresearch.TrustHub.Controllers.FromApp.VPNServiceHandler;

/**
 * Created by sheidbri on 5/27/15.
 */
class CertificateReporter
{
    private int mPort;
    private String mHostname;
    public CertificateReporter(String hostname, int port) {
        mHostname = hostname;
        mPort = port;
    }

    public boolean reportCertificate(String hostname, String local, String country, List<X509Certificate> certChain)
    {
        boolean reportSent = false;
        try {

            // Init SSL
            SSLContext sslcontext = SSLContext.getInstance("SSL");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            char[] pass = {'p','a','s','s'};
            kmf.init(null, pass);
            sslcontext.init(kmf.getKeyManagers(),
                    new TrustManager[]{new TrustEveryone()},
                    null);

            // Create Socket, Connnect, and TLS Handshake
            SocketChannel reportChannel = SocketChannel.open();
            boolean succeeded = VPNServiceHandler.getVPNServiceHandler().protect(reportChannel.socket());
            reportChannel.connect(new InetSocketAddress(mHostname, mPort));

            SSLSocket reportingSocket = (SSLSocket) sslcontext.getSocketFactory().
                    createSocket(reportChannel.socket(), mHostname, mPort, true);

            Log.d("TrustHub", "Protected: " + succeeded);
            reportingSocket.startHandshake();

            // get output stream for socket and data for report
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(reportingSocket.getOutputStream()));
            StringBuilder postBody = makeReportBody(hostname, local, country, certChain);

            // Create header for body
            out.write("POST /mobilereport.php HTTP/1.1\r\n");
            out.write("host:" + mHostname + "\r\n");
            out.write("Content-Type:application/x-www-form-urlencoded\r\n");
            out.write("Content-Length:" + postBody.length() + "\r\n\r\n");

            // Send report body
            out.write(postBody.toString());
            out.flush();
            reportSent = true;
            reportingSocket.close();
        } catch (IOException e) {
            Log.d("TrustHub", " IO Exception: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            Log.d("TrustHub", " NoSuchAlgorithmException Exception: " + e.getMessage());
        } catch (KeyManagementException e) {
            Log.d("TrustHub", " KeyManagementException Exception: " + e.getMessage());
        } catch (UnrecoverableKeyException e) {
            Log.d("TrustHub", " UnrecoverableKeyException Exception: " + e.getMessage());
        } catch (KeyStoreException e) {
            Log.d("TrustHub", " KeyStoreException Exception: " + e.getMessage());
        }
        return reportSent;
    }

    private StringBuilder makeReportBody(String hostname, String local, String country, List<X509Certificate> certChain)
    {
        StringBuilder reportBody = new StringBuilder();
        reportBody.append("certificate=");

        // Format to OpenSSL-compatible URL encoded certificate chain
        for (int i = 0; i < certChain.size(); i++) {
            reportBody.append("-----BEGIN CERTIFICATE-----\n");
            reportBody.append(encodeCertificate(certChain.get(i)));
            reportBody.append("-----END CERTIFICATE-----\n");
        }
        //reportBody.append("nothing");

        // Add host
        reportBody.append("&host=");
        reportBody.append(hostname);

        // Add GPS location
        reportBody.append("&city=");
        reportBody.append(local);
        reportBody.append("&country=");
        reportBody.append(country);
        reportBody.append("&experimentID=ORCA");
        return reportBody;
    }

    private String encodeCertificate(X509Certificate cert)
    {
        String output = "Unknown";
        try
        {
            output = URLEncoder.encode(Base64.encodeToString(cert.getEncoded(), Base64.DEFAULT), "UTF-8");
        }
        catch (Exception e)
        {
            Log.d("TrustHub", "Failed to encode certificate: " + e.getMessage());
        }
        return output;
    }
}
