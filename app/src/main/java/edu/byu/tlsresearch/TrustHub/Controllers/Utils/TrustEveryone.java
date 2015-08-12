package edu.byu.tlsresearch.TrustHub.Controllers.Utils;

import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * Created by sheidbri on 5/27/15.
 */
public class TrustEveryone implements X509TrustManager
{
    public void checkClientTrusted(X509Certificate[] chain,
                                   String authenticationType)
    {
    }

    public void checkServerTrusted(X509Certificate[] chain,
                                   String authenticationType)
    {
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        return new java.security.cert.X509Certificate[]{};
    }
}
