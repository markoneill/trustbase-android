package edu.byu.tlsresearch.TrustHub.Utils;

import android.content.res.AssetManager;
import android.util.Log;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.x509.X509Certificate;

/**
 * Created by sheidbr on 8/5/15.
 */
public class CertSpoofer
{
    private static KeyStore mKS;
    private static KeyPair mNewCertPair;

    public static X509Certificate generate()
    {

        return null;
    }

    public static void loadKeyStore(AssetManager assets)
    {
        try
        {
            mKS = KeyStore.getInstance("PKCS12");
            mKS.load(assets.open("TrustHubstore.p12"), "password".toCharArray());
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        catch (KeyStoreException e)
        {
            e.printStackTrace();
        }
        catch (CertificateException e)
        {
            e.printStackTrace();
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
    }

    public static KeyStore generateCert(java.security.cert.X509Certificate toCopy)
    {
        try
        {
            X509Certificate newCert;
            //Create a KeyPair for the new certificate
            if (mNewCertPair == null)
            {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048, new SecureRandom());
                mNewCertPair = keyGen.generateKeyPair();
            }
            //Load our CA for signing
            Certificate caCert;
            caCert = mKS.getCertificate("TrustHubCA");
            PrivateKey privKey = (PrivateKey) mKS.getKey("TrustHubCA", "password".toCharArray());

            newCert = new X509Certificate(toCopy.getEncoded());
            newCert.setPublicKey(mNewCertPair.getPublic());
            newCert.setIssuerDN((new X509Certificate(caCert.getEncoded())).getSubjectDN());
            //Log.d("CertSpoofer", newCert.getSignatureAlgorithm().toString());
            newCert.sign(newCert.getSignatureAlgorithm(), privKey);

            KeyStore newKS = KeyStore.getInstance("PKCS12");
            newKS.load(null, null);
            Certificate[] chain = {newCert, caCert};
            newKS.setKeyEntry("ForgedCert", mNewCertPair.getPrivate(), "password".toCharArray(), chain);
            return newKS;
        }
        catch (Exception e)
        {
            String TAG = "CertSpoofer";
            Log.d(TAG, e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}
