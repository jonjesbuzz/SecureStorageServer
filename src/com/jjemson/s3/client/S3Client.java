package com.jjemson.s3.client;

import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;
import com.jjemson.s3.S3Protocol.*;
import com.jjemson.s3.S3Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;


/**
 * S3Client
 *
 * @author Jonathan Jemson
 * @version 1.0
 */
public class S3Client {

    private static ExtensionRegistry registry = ExtensionRegistry.newInstance();

    static {
        registry.add(CheckinRequest.ciRequest);
        registry.add(CheckinResponse.ciResponse);
        registry.add(CheckoutResponse.coResponse);
        registry.add(CheckoutRequest.coRequest);
        registry.add(LoginResponse.login);
        registry.add(LoginRequest.login);
    }

    private String hostname;
    private int port;

    private Socket socket;
    private PrivateKey privateKey;
    private OutputStream outputStream;
    private InputStream inputStream;

    private static void printInfo(String s) {
        System.out.println("[Client] " + s);
    }
    private static void printError(String s) {
        System.err.println("[Client] " + s);
    }

    public S3Client(PrivateKey privateKey) {
        this("localhost", 8088, privateKey);
    }
    public S3Client(String host, int port, PrivateKey privateKey) {
        this.hostname = host;
        this.port = port;
        this.privateKey = privateKey;
    }

    public void connect(String username, Certificate myCert) {
        try {
            socket = new Socket(hostname, port);
            inputStream = socket.getInputStream();
            outputStream = socket.getOutputStream();
        } catch (IOException ioe) {
            printError("Could not connect to " + hostname + ":" + port + ".");
            System.exit(1);
            return;
        }

        // TODO Perform mutual authentication.
        try {
            ByteString cert = ByteString.copyFrom(myCert.getEncoded());
            LoginRequest login = LoginRequest.newBuilder().setUser(username).setClientCert(cert).build();
            S3Message msg = S3Message.newBuilder()
                    .setType(S3Message.MessageType.LoginRequest)
                    .setExtension(LoginRequest.login, login).build();
            msg.writeDelimitedTo(outputStream);
            this.socket.getOutputStream().flush();

            // TODO Receive server's authentication

            LoginResponse response = null;
            while (response == null) {
                S3Message mg = S3Message.parseDelimitedFrom(inputStream, registry);
                response = mg.getExtension(LoginResponse.login);
            }
            Certificate server = S3Security.reconstructEncodedCertificate(response.getServerCert().toByteArray());
            if (!S3Security.verifyCertificate(username, "cs6238", server)) {
                printError("Could not verify certificate");
                System.exit(1);
            }

            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, server);
                outputStream = new CipherOutputStream(outputStream, cipher);
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                inputStream = new CipherInputStream(inputStream, cipher);

            } catch (GeneralSecurityException gse) {
                printError("Failed to encrypt the link.");
                gse.printStackTrace();
            }
        } catch (IOException ioe) {
            printError("Could not communicate with server");
            ioe.printStackTrace();
            return;
        } catch (CertificateEncodingException cee) {
            cee.printStackTrace();
            return;
        }

        // TODO Encrypt the link
        // TODO Ask if we can use SSLSocket in Java
    }

    public File checkout(String filename) {
        // TODO Receive the file from the S3 Server
        // TODO Save file to disk
        // TODO Return File object to user
        return null;
    }

    public boolean checkin(File file,  String filename, Security flag) {
        byte[] fileData;
        ByteString fileString;
        try {
            fileData = Files.readAllBytes(file.toPath());
            fileString = ByteString.copyFrom(fileData);
        } catch (IOException ioe) {
            printError("Could not read file at " + file.getAbsolutePath());
            ioe.printStackTrace();
            return false;
        }
        CheckinRequest checkIn = CheckinRequest
                .newBuilder()
                .setDocumentId(filename)
                .setSecurity(flag)
                .setFileData(fileString)
                .build();
        S3Message message = S3Message
                .newBuilder()
                .setExtension(CheckinRequest.ciRequest, checkIn)
                .setType(S3Message.MessageType.CheckinRequest)
                .build();
        try {
            printInfo("Writing checkin to socket:\n" + message);
            message.writeDelimitedTo(socket.getOutputStream());
        } catch (IOException ioe) {
            printError("Socket write failed");
            ioe.printStackTrace();
            return false;
        }
        return true;
    }

    public boolean delegate(String filename, String clientID, int timeInterval, boolean propagate) {
        // TODO Add delegation to a file
        return false;
    }

    public boolean delete(String filename) {
        // TODO Delete file
        return false;
    }

    public void close() {
        // TODO Write updated copies to server

        // Then close the connection.
        try {
            this.socket.close();
        } catch (IOException ioe) {
            printError("Could not close socket.");
            ioe.printStackTrace();
        }
    }

    public static void main(String... args) {
        if (args.length < 1) {
            printError("Usage: java -jar s3server.jar [username]");
            System.exit(1);
            return;
        }
        String username = args[0];
        printInfo("S3 client started.");
        Certificate certificate = null;
        PrivateKey privateKey = null;
        try {
            certificate = S3Security.getCertificate(username, "cs6238", username);
            privateKey = S3Security.getKeyPair(username, "cs6238", username).getPrivate();
            if (certificate == null || privateKey == null) {
                printError("Could not open own certificate");
                return;
            }
        } catch (IOException ioe) {
            printError("Could not open client certificate.");
            return;
        }
        S3Client client = new S3Client(privateKey);
        client.connect(username, certificate);
//        client.checkin(new File("/Users/jonathan/swap.c"), "swap.c", Security.NONE);
        client.close();
    }
}