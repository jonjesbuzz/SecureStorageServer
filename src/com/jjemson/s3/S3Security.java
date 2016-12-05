package com.jjemson.s3;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * S3Security
 *
 * @author Jonathan Jemson
 * @version 1.0
 */
public class S3Security {

    private static void printError(String s) {
        System.err.println("[Security] " + s);
    }

    public static Certificate getCertificate(String storeName, String storePassword, String username) throws IOException {
        try {
            KeyStore ks = loadKeyStore(storeName, storePassword);
            PrivateKey privateKey = (PrivateKey) ks.getKey(username, storePassword.toCharArray());
            if (privateKey == null) {
                return null;
            }
            Certificate certificate = ks.getCertificate(username);
            if (!verifyWithCA(ks, certificate)) {
                return null;
            }
            return certificate;
        } catch (GeneralSecurityException gse) {
            printError("Security exception");
            gse.printStackTrace();
            return null;
        }
    }

    public static KeyPair getKeyPair(String storeName, String storePassword, String username) throws IOException {
        try {
            KeyStore ks = loadKeyStore(storeName, storePassword);
            PrivateKey privateKey = (PrivateKey) ks.getKey(username, storePassword.toCharArray());
            if (privateKey == null) {
                return null;
            }
            Certificate certificate = ks.getCertificate(username);
            if (certificate == null) {
                return null;
            }
            if (!verifyWithCA(ks, certificate)) {
                return null;
            }
            return new KeyPair(certificate.getPublicKey(), privateKey);
        } catch (GeneralSecurityException gse) {
            printError("Security exception");
            gse.printStackTrace();
            return null;
        }
    }

    public static boolean verifyCertificate(String storeName, String storePassword, Certificate c) throws IOException {
        try {
            KeyStore ks = loadKeyStore(storeName, storePassword);
            return verifyWithCA(ks, c);
        } catch (GeneralSecurityException gse) {
            printError("Security exception");
            gse.printStackTrace();
            return false;
        }
    }

    public static KeyStore loadKeyStore(String storeName, String password)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        java.io.FileInputStream fis = null;
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            fis = new java.io.FileInputStream("./certs/" + storeName + "/" + storeName + ".jks");
            ks.load(fis, password.toCharArray());
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        return ks;
    }

    private static boolean verifyWithCA(KeyStore keyStore,  Certificate certificate) {
        try {
            Certificate root = keyStore.getCertificate("root");
            if (root == null) return false;
            certificate.verify(root.getPublicKey());
        } catch (SignatureException se) {
            printError("Signature could not be verified as CA signature.  Aborting.");
            return false;
        } catch (KeyStoreException kse) {
            printError("Keystore could not be used.");
            return false;
        } catch (GeneralSecurityException gse) {
            printError("A security exception occurred.");
            gse.printStackTrace();
            return false;
        }
        return true;

    }

    public static Certificate reconstructEncodedCertificate(byte[] encodedKey) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return factory.generateCertificate(new ByteArrayInputStream(encodedKey));
        } catch (CertificateException ce) {
            printError("Certificate generation failed.");
            ce.printStackTrace();
        }
        return null;
    }
}
