package com.jjemson.s3.server;

import com.google.protobuf.ExtensionRegistry;
import com.jjemson.s3.S3Security;

import java.io.IOException;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;

/**
 * S3Server
 *
 * @author Jonathan Jemson
 * @version 1.0
 */
public class S3Server {

    private ServerSocket socket;
    private KeyPair serverKeys;

    public S3Server() {
        this(8088);
    }

    private static void printInfo(String s) {
        System.out.println("[Server] " + s);
    }
    private static void printError(String s) {
        System.err.println("[Server] " + s);
    }

    public S3Server(int port) {
        try {
            // TODO Secure this password somehow…
            this.serverKeys = S3Security.getKeyPair("server", "cs6238", "S3 Server");
            this.socket = new ServerSocket(port);
            if (this.serverKeys == null) {
                System.exit(1);
            }
        } catch (IOException ioe) {
            printError("Could not bind to port " + port + ".");
            ioe.printStackTrace();
        }
    }

    public void startServer() {
        printInfo("Started server on port " + this.socket.getLocalPort());
        Socket s;
        while (true) {
            try {
                s = socket.accept();
                printInfo("Connected to client: " + s.getInetAddress());
                new Thread(new S3Session(s, serverKeys)).start();
            } catch (IOException ioe) {
                printError("Failed to accept socket connection.");
            }
        }
    }

    public static void main(String[] args) {
        S3Server s3Server = new S3Server();
        s3Server.startServer();
    }

}
