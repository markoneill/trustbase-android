package edu.byu.tlsresearch.TrustHub.API;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Created by sheidbri on 4/30/15.
 */
public interface PluginInterface
{
    public enum POLICY_RESPONSE
    {
        INVALID,
        VALID,
        VALID_PROXY
    }

    POLICY_RESPONSE check(List<X509Certificate> cert_chain);
}
