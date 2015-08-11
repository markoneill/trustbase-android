package edu.byu.tlsresearch.TrustHub.Utils;

import android.content.res.AssetManager;
import android.util.Log;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.x509.X509Certificate;

/**
 * Created by sheidbr on 8/5/15.
 */
public class CertSpoofer
{
    public static KeyStore mKS;
    private static KeyPair mNewCertPair;

    private static String TAG = "CertSpoofer";

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
            //Log.d(TAG, "Keystore loaded");
        } catch (IOException e)
        {
            e.printStackTrace();
        } catch (KeyStoreException e)
        {
            e.printStackTrace();
        } catch (CertificateException e)
        {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
    }

    public static KeyStore generateCert(java.security.cert.X509Certificate toCopy)
    {
        //Log.d(TAG, "Start");
        try
        {
            X509Certificate newCert = null;
            //Create a KeyPair for the new certificate
            if (mNewCertPair == null)
            {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048, new SecureRandom());
                mNewCertPair = keyGen.generateKeyPair();
            }
            //Load our CA for signing
            Certificate caCert = null;
            caCert = mKS.getCertificate("TrustHubCA");
            PrivateKey privKey = (PrivateKey) mKS.getKey("TrustHubCA", "password".toCharArray());
            KeyPair both = new KeyPair(caCert.getPublicKey(), privKey);
            try
            {
                newCert = new X509Certificate(toCopy.getEncoded());
            } catch (CertificateException e)
            {
                e.printStackTrace();
            }

            newCert = new X509Certificate(toCopy.getEncoded());
            newCert.setPublicKey(mNewCertPair.getPublic());

            Name issuer = new Name();
            issuer.addRDN(ObjectID.country, "US");
            issuer.addRDN(ObjectID.organization, "TrustHub");
            issuer.addRDN(ObjectID.organizationalUnit, "TrustHub");
            issuer.addRDN(ObjectID.commonName, "TrustHub");

            newCert.setIssuerDN(issuer);

            newCert.sign(AlgorithmID.sha256WithRSAEncryption, privKey);

            //Log.d(TAG, mNewCertPair.getPublic().toString());
            //Log.d(TAG, newCert.toString());

            KeyStore newKS = KeyStore.getInstance("PKCS12");
            newKS.load(null, null);
            Certificate[] chain = {newCert, caCert};
            newKS.setKeyEntry("ForgedCert", mNewCertPair.getPrivate(), "password".toCharArray(), chain);
            return newKS;
        }
        catch (Exception e)
        {
            Log.d(TAG, e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}
