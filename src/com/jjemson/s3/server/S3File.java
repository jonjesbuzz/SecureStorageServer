package com.jjemson.s3.server;

import com.jjemson.s3.S3Protocol.CheckinRequest;
import com.jjemson.s3.S3Protocol.Security;
import com.jjemson.s3.S3Security;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.util.EnumSet;

/**
 * S3File
 *
 * @author Jonathan Jemson
 * @version 1.0
 */
class S3File {

    static byte[] iv = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    static IvParameterSpec ivspec = new IvParameterSpec(iv);

    private String owner;
    private String filename;
    private Security fileSec;

    private File file;

    protected S3File(String owner, String filename, Security fileSec, byte[] fileData) {
        this.owner = owner;
        this.filename = filename;
        this.fileSec = fileSec;
        this.file = new File(this.getDocumentID());
        try {
            if (this.file.exists()) {
                this.file.delete();
            }
            this.file.getParentFile().mkdirs();
            this.file.createNewFile();
            OutputStream fos = new FileOutputStream(this.file);
            SecretKey key = null;
            if (fileSec == Security.ALL || fileSec == Security.INTEGRITY || fileSec == Security.CONFIDENTIALITY) {
                try {
                    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                    keyGenerator.init(128);
                    key = keyGenerator.generateKey();
                } catch (NoSuchAlgorithmException nsae) {
                    nsae.printStackTrace();
                }
            }
            EnumSet<Security> securities = EnumSet.of(fileSec);
            if (fileSec == Security.NONE || fileSec == Security.INTEGRITY) {
                fos.write(fileData);
            }
            if (securities.contains(Security.CONFIDENTIALITY) || securities.contains(Security.ALL)) {
                try {
                    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), "AES"), ivspec);
                    CipherOutputStream cipherOutputStream = new CipherOutputStream(fos, c);
                    cipherOutputStream.write(fileData);
                    cipherOutputStream.close();

                    KeyPair serverKeys = S3Security.getKeyPair("server", "cs6238", "S3 Server");
                    PublicKey key1 = serverKeys.getPublic();
                    Cipher pkCipher = Cipher.getInstance("RSA");
                    pkCipher.init(Cipher.ENCRYPT_MODE, key1);

                    File keyFile = new File(this.file.getParentFile(), "keys/" + this.filename + ".key");
                    if (keyFile.exists()) {
                        keyFile.delete();
                    }
                    keyFile.getParentFile().mkdirs();
                    keyFile.createNewFile();
                    FileOutputStream keyOS = new FileOutputStream(keyFile);
                    CipherOutputStream cipherOutputStream1 = new CipherOutputStream(keyOS, pkCipher);
                    cipherOutputStream1.write(key.getEncoded());
                    cipherOutputStream1.close();
                    keyOS.close();
                } catch (GeneralSecurityException nsae) {
                    System.err.println("No AES key could be generated");
                    nsae.printStackTrace();
                }

            }
            if (securities.contains(Security.INTEGRITY) || securities.contains(Security.ALL)) {
                try {
                    KeyPair serverKeys = S3Security.getKeyPair("server", "cs6238", "S3 Server");
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(serverKeys.getPrivate());
                    signature.update(fileData);
                    byte[] signed = signature.sign();
                    File sigFile = new File(this.file.getParentFile(), "keys/" + this.filename + ".sig");
                    if (sigFile.exists()) {
                        sigFile.delete();
                    }
                    FileOutputStream fileOutputStream = new FileOutputStream(sigFile);
                    fileOutputStream.write(signed);
                    fileOutputStream.close();
                } catch (GeneralSecurityException gse) {
                    System.err.println("Signature error.");
                    gse.printStackTrace();
                }
            }
            fos.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    protected S3File(String owner, CheckinRequest checkIn) {
        this(owner, checkIn.getDocumentId(), checkIn.getSecurity(), checkIn.getFileData().toByteArray());
    }

    public void delete() {
        File keyFile = new File(this.file.getParentFile(), "keys/" + this.filename + ".key");
        if (keyFile.exists()) {
            keyFile.delete();
        }
        File sigFile = new File(keyFile.getParentFile(), this.filename + ".sig");
        if (sigFile.exists()) {
            sigFile.delete();
        }
        this.file.delete();
    }

    public String getDocumentID() {
        return documentID(this.owner, this.filename);
    }

    public static String documentID(String owner, String filename) {
        return owner + "/" + filename;
    }

    public byte[] getFileData() {
        try {
            EnumSet<Security> securities = EnumSet.of(fileSec);
            byte[] fileData = Files.readAllBytes(file.toPath());
            File keyFile = new File(this.file.getParentFile(), "keys/" + this.filename + ".key");
            File sigFile = new File(this.file.getParentFile(), "keys/" + this.filename + ".sig");
            if (securities.contains(Security.CONFIDENTIALITY) || securities.contains(Security.ALL)) {
                ByteArrayInputStream dataStream = new ByteArrayInputStream(fileData);
                FileInputStream keyStream = new FileInputStream(keyFile);

                KeyPair serverKeys = S3Security.getKeyPair("server", "cs6238", "S3 Server");
                PrivateKey key1 = serverKeys.getPrivate();
                Cipher pkCipher = Cipher.getInstance("RSA");
                pkCipher.init(Cipher.DECRYPT_MODE, key1);
                CipherInputStream keyCipher = new CipherInputStream(keyStream, pkCipher);
                byte[] keyData = getBytesFromInputStream(keyCipher);

                Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyData, "AES"), ivspec);
                CipherInputStream dataInput = new CipherInputStream(dataStream, c);

                byte[] deciphered = getBytesFromInputStream(dataInput);
                fileData = deciphered;
            }
            if (securities.contains(Security.INTEGRITY) || securities.contains(Security.ALL)) {
                FileInputStream sigStream = new FileInputStream(sigFile);
                KeyPair serverKeys = S3Security.getKeyPair("server", "cs6238", "S3 Server");
                PublicKey publicKey = serverKeys.getPublic();
                byte[] sigBytes = getBytesFromInputStream(sigStream);
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initVerify(publicKey);
                signature.update(fileData);
                boolean verified = signature.verify(sigBytes);
                if (!verified) {
                    System.err.println();
                    return null;
                }
            }
            return fileData;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] getBytesFromInputStream(InputStream is) throws IOException
    {
        try (ByteArrayOutputStream os = new ByteArrayOutputStream();)
        {
            byte[] buffer = new byte[0xFFFF];

            for (int len; (len = is.read(buffer)) != -1;)
                os.write(buffer, 0, len);

            os.flush();

            return os.toByteArray();
        }
    }

    public String getOwner() {
        return owner;
    }

    public Security getFileSec() {
        return fileSec;
    }

    @Override
    public String toString() {
        return "File: " + file.getName() + "\n" +
                "Owner: " + owner + "\n" +
                "Security: " + fileSec.toString() + "\n" +
                "Document ID" + filename;
    }
}
