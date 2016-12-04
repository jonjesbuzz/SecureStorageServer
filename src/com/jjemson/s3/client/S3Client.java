package com.jjemson.s3.client;

import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;
import com.jjemson.s3.S3Protocol.*;
import com.jjemson.s3.S3Security;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.HashSet;
import java.util.Set;


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
        registry.add(DelegationRequest.dRequest);
        registry.add(DeleteRequest.delRequest);
        registry.add(DeleteResponse.delResponse);
    }

    private String hostname;
    private int port;

    private Socket socket;
    private PrivateKey privateKey;
    private OutputStream outputStream;
    private InputStream inputStream;

    private Set<S3FileInfo> openFiles;

    private boolean closed;

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
        this.openFiles = new HashSet<>();
        closed = true;
    }

    public void connect(String username, Certificate myCert) {
        try {
            socket = new Socket(hostname, port);
            inputStream = socket.getInputStream();
            outputStream = socket.getOutputStream();

            // Even if the user doesn't explicitly close, we will.
            Runtime.getRuntime().addShutdownHook(new Thread(this::close));

            closed = false;

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

//            try {
//                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//                cipher.init(Cipher.ENCRYPT_MODE, server);
//                outputStream = new CipherOutputStream(outputStream, cipher);
//                cipher.init(Cipher.DECRYPT_MODE, privateKey);
//                inputStream = new CipherInputStream(inputStream, cipher);
//
//            } catch (GeneralSecurityException gse) {
//                printError("Failed to encrypt the link.");
//                gse.printStackTrace();
//            }
        } catch (IOException ioe) {
            printError("Could not communicate with server");
            ioe.printStackTrace();
            return;
        } catch (CertificateEncodingException cee) {
            cee.printStackTrace();
            return;
        }

        // TODO Encrypt the link
    }

    public File checkout(String filename) {
        return this.checkout(filename, null);
    }

    public File checkout(String filename, String user) {
        CheckoutRequest request = CheckoutRequest.newBuilder().setDocumentId(filename).build();
        // Delegation.
        if (user != null && !user.equals("")) {
            request = CheckoutRequest.newBuilder().setDocumentId(filename).setOwner(user).build();
        }
        S3Message msg = S3Message.newBuilder().setType(S3Message.MessageType.CheckoutRequest).setExtension(CheckoutRequest.coRequest, request).build();
        try {
            msg.writeDelimitedTo(outputStream);
            msg = null;
        } catch (IOException ioe) {

        }

        while (msg == null) {
            try {
                msg = S3Message.parseDelimitedFrom(inputStream, registry);
            } catch (IOException ioe) {
            }
        }
        printInfo("Message:\n" + msg);
        try {
            CheckoutResponse response = msg.getExtension(CheckoutResponse.coResponse);
            if (!response.getSuccess()) {
                return null;
            }
            printInfo("Response:\n" + response);
            File file = new File(filename);
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(response.getFileData().toByteArray());
            fileOutputStream.close();
            openFiles.add(new S3FileInfo(file, response.getSecurity()));
            return file;
        } catch (IOException ioe) {
        }
        return null;
    }

    public boolean checkin(File file,  String filename, Security flag) {
        if (!file.exists()) {
            return false;
        }
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
        openFiles.remove(file);
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
            message.writeDelimitedTo(outputStream);
            S3Message resp = null;
            while (resp == null) {
                resp = S3Message.parseDelimitedFrom(inputStream, registry);
            }
            printInfo("" + resp);
            return resp.getType() == S3Message.MessageType.CheckinResponse && resp.getExtension(CheckinResponse.ciResponse).getSuccess();
        } catch (IOException ioe) {
            printError("Socket I/O failed");
            ioe.printStackTrace();
            return false;
        }
//        return true;
    }

    public boolean delegate(String filename, String clientID, int timeInterval, boolean propagate) {
        DelegationRequest request = DelegationRequest.newBuilder()
                .setDocumentId(filename)
                .setClientUser(clientID)
                .setDuration(timeInterval)
                .setPropagate(propagate)
                .build();
        S3Message msg = S3Message.newBuilder()
                .setType(S3Message.MessageType.DelegationRequest)
                .setExtension(DelegationRequest.dRequest, request)
                .build();
        try {
            msg.writeDelimitedTo(outputStream);
        } catch (IOException ioe) {
            printError("Could not deliver delegation to server.");
            ioe.printStackTrace();
            return false;
        }
        return true;
    }

    public boolean delete(String filename) {
        DeleteRequest request = DeleteRequest.newBuilder()
                .setDocumentId(filename)
                .build();
        S3Message msg = S3Message.newBuilder()
                .setType(S3Message.MessageType.DeleteRequest)
                .setExtension(DeleteRequest.delRequest, request)
                .build();

        File file = new File(filename);
        if (file.exists()) {
            file.delete();
            openFiles.remove(new S3FileInfo(file, null));
        }

        try {
            msg.writeDelimitedTo(outputStream);
            S3Message resp = null;
            while (resp == null) {
                resp = S3Message.parseDelimitedFrom(inputStream, registry);
            }
            printInfo("" + resp);
            return resp.getType() == S3Message.MessageType.DeleteResponse && resp.getExtension(DeleteResponse.delResponse).getSuccess();
        } catch (IOException ioe) {
            printError("Could not send delete request");
            ioe.printStackTrace();
            return false;
        }
//        return true;
    }

    public void close() {
        if (closed) {
            return;
        }
        for (S3FileInfo file : openFiles) {
            checkin(file.file, file.file.getName(), file.security);
        }
        openFiles.clear();
        // Then close the connection.
        try {
            S3Message msg = S3Message.newBuilder()
                    .setType(S3Message.MessageType.CloseRequest)
                    .build();
            msg.writeDelimitedTo(outputStream);
            this.socket.close();
            closed = true;
        } catch (IOException ioe) {
            printError("Could not close socket.");
            ioe.printStackTrace();
        }
    }

    // Called before JVM cleans it up; make absolutely sure connection is closed.
    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        this.close();
    }

    public static void main(String... args) {
        if (args.length < 1) {
            printError("Usage: java -jar s3client.jar [username]");
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
        if (username.equals("client1")) {
            client.checkin(new File("/Users/jonathan/swap.c"), "swap.c", Security.ALL);
            client.delegate("swap.c", "client2",120 * 60 * 60, false);
        }
        if (username.equals("client2")) {
            client.checkout("swap.c", "client1");
        }
        client.close();
    }

    private class S3FileInfo {
        private File file;
        private Security security;
        public S3FileInfo(File f, Security s) {
            this.file = f;
            this.security = s;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof S3FileInfo) {
                return this.file.equals(((S3FileInfo)obj).file);
            }
            return false;
        }

        @Override
        public int hashCode() {
            return this.file.hashCode();
        }
    }
}