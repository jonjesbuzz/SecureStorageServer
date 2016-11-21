package com.jjemson.s3.client;

import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;
import com.jjemson.s3.S3Protocol.*;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;

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
    }

    private String hostname;
    private int port;

    private Socket socket;

    private static void printInfo(String s) {
        System.out.println("[Client] " + s);
    }
    private static void printError(String s) {
        System.err.println("[Client] " + s);
    }

    public S3Client() {
        this("localhost", 8088);
    }

    public S3Client(String host, int port) {
        this.hostname = host;
        this.port = port;
    }

    public void connect(String username) {
        try {
            socket = new Socket(hostname, port);
        } catch (IOException ioe) {
            printError("Could not connect to " + hostname + ":" + port + ".");
            System.exit(1);
            return;
        }

        // TODO Perform mutual authentication.
        try {
            Login login = Login.newBuilder().setUser(username).build();
            S3Message msg = S3Message.newBuilder()
                    .setType(S3Message.MessageType.Login)
                    .setExtension(Login.login, login).build();
            msg.writeDelimitedTo(socket.getOutputStream());
            this.socket.getOutputStream().flush();

            // TODO Receive server's authentication

            printInfo("Login requested as " + username + "; message:\n" + msg);
        } catch (IOException ioe) {
            printError("Could not communicate with server");
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
        printInfo("S3 client started.");
        S3Client client = new S3Client();
        client.connect("jonathan");
        client.checkin(new File("/Users/jonathan/swap.c"), "swap.c", Security.NONE);
        client.close();
    }
}