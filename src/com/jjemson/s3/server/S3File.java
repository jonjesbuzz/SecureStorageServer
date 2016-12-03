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
import java.util.*;

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
    private Map<String, S3FileDelegate> delegates;

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
            System.out.println(securities);
            if (fileSec == Security.NONE || fileSec == Security.INTEGRITY) {
                System.out.println("Writing file in the clear.");
                fos.write(fileData);
            }
            if (securities.contains(Security.CONFIDENTIALITY) || securities.contains(Security.ALL)) {
                try {
                    System.out.println("Writing encrypted file.");
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
                System.out.println("Generating signature for cleartext.");
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
        this.delegates = new HashMap<>();
    }

    protected S3File(String owner, CheckinRequest checkIn) {
        this(owner, checkIn.getDocumentId(), checkIn.getSecurity(), checkIn.getFileData().toByteArray());
    }

    public void delete() {
        File keyFile = new File(this.file.getParentFile(), "keys/" + this.filename + ".key");
        if (keyFile.exists()) {
            keyFile.delete();
        }
        this.file.delete();
    }

    public String getDocumentID() {
        return documentID(this.owner, this.filename);
    }

    public static String documentID(String owner, String filename) {
        return owner + "/" + filename;
    }

    public void delegate(String user, int timeInterval, boolean propagate) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, timeInterval);
        delegates.put(user, new S3FileDelegate(user, calendar.getTime(),  propagate));
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

    public boolean checkDelegateForUser(String user) {
        S3FileDelegate delegate = delegates.get(user);
        if (delegate == null) {
            return false;
        }
        Date now = new Date();
        if (now.after(delegate.validUntil)) {
            delegates.remove(user);
            return false;
        }
        return true;
    }

    public Security getFileSec() {
        return fileSec;
    }

    private static class S3FileDelegate {
        private String user;
        private Date validUntil;
        private boolean propagate;

        S3FileDelegate(String user, Date validUntil, boolean propagate) {
            this.user = user;
            this.validUntil = validUntil;
            this.propagate = propagate;
        }
    }
}
