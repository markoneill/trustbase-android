package edu.byu.tlsresearch.TrustHub.PluginTest.Plugins;

import android.content.ContextWrapper;
import android.content.res.AssetManager;
import android.util.Log;


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;

/**
 * Created by ben on 10/30/15.
 * This plugin allows the whitelisting of specified certificates.
 */
public class WhitelistPlugin implements PluginInterface {

    private final String TAG = "WhitelistPlugin";

    private final String assets_dir = "WhitelistCerts";   //Whitelist directory
    private final String PEM_extension = ".*\\.pem";    //Regex for matching pem files

    ContextWrapper base;    //Base ContextWrapper.  Used to access file system.

    public WhitelistPlugin(ContextWrapper cw)
    {
        base = cw;
    }

    @Override
    public POLICY_RESPONSE check(List<X509Certificate> cert_chain) {
        X509Certificate cert;   //Leaf certificate

        //Get the leaf certificate
        if((cert_chain == null) || (cert_chain.size() < 1))   //Check that there are certificates
        {
            Log.e(TAG, "Null or empty certificate_chain");
            return POLICY_RESPONSE.INVALID;
        }
        else
            cert = cert_chain.get(0);

        //Verify host name
        //Check against the common host name
        //Check against its alternatives
        //TODO: Implement this later when we can get the host name

        //Hash the leaf certificate
        byte[] leaf_hash = hash_certificate(cert);

        //Get a list of all whitelisted certs
        AssetManager am = base.getAssets();     //Asset manager
        String[] certs;
        try {
            certs = am.list(assets_dir);
        }
        catch(IOException e)
        {
            Log.e(TAG, "Invalid whitelist directory");
            return POLICY_RESPONSE.INVALID;
        }

        //Hash certificates and compare them to the leaf certificate hash
        for(int i = 0; i < certs.length; i++)
        {
            if(certs[i].matches(PEM_extension)) //Only check valid file types
            {
                try {
                    X509Certificate list_cert;
                    InputStream cfile = am.open(assets_dir + File.separator + certs[i]);  //Open file
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    list_cert = (X509Certificate) cf.generateCertificate(cfile);    //Extract the certificate
                    byte[] list_hash = hash_certificate(list_cert); //Hash extracted certificate
                    if(MessageDigest.isEqual(leaf_hash, list_hash)) //Compare hashes
                    {
                        Log.d(TAG, "Match found. Cert matches " + certs[i]);
                        return POLICY_RESPONSE.VALID;   //Hashes are equal.  Return valid
                    }
                }
                catch (IOException e) {
                    Log.e(TAG, "Invalid file: " + certs[i]);
                }
                catch (CertificateException e) {
                    Log.e(TAG, "Certificate exception in file: " + certs[i]);
                }
            }
        }

        //Leaf certificate did not match any whitelisted certificates.  Return INVALID.
        Log.d(TAG, "No match found for certificate");
        return POLICY_RESPONSE.INVALID;
    }

    //Turn a certificate to a byte array
    private byte[] get_certificate_bytes(X509Certificate cert)
    {
        ByteArrayOutputStream holder = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] result = null;
        try {
            out = new ObjectOutputStream(holder);
            out.writeObject(cert);
            result = holder.toByteArray();
        }
        catch (IOException e) {
            Log.e(TAG, "Error putting cert in byte array");
        }
        finally {
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ex) {
                // ignore close exception
            }
            try {
                holder.close();
            } catch (IOException ex) {
                // ignore close exception
            }
        }

        return result;
    }

    /**
     *  This function hashes a certificate.
     * @param cert  Certificate to be hashed
     * @return      Hashed certificate
     */
    private byte[] hash_certificate(X509Certificate cert)
    {
        byte[] hash1 = null;
        MessageDigest digester;
        try {
            digester = MessageDigest.getInstance("SHA-256");
            digester.reset();
            hash1 = digester.digest(get_certificate_bytes(cert));
        }
        catch (NoSuchAlgorithmException e)
        {
            Log.e(TAG, "SHA-256 algorithm not found");
        }
        return hash1;
    }

}

