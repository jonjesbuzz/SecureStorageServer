package com.jjemson.s3.server;

import com.jjemson.s3.S3Security;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;

/**
 * S3Server
 *
 * @author Jonathan Jemson
 * @version 1.0
 */
public class S3Server {

    private ServerSocket socket;
    private KeyPair serverKeys;
    private SSLSocketFactory socketFactory;

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
//            this.socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            KeyStore keyStore = S3Security.loadKeyStore("server", "cs6238");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, "cs6238".toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(keyStore);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            this.socketFactory = sslContext.getSocketFactory();
            this.serverKeys = S3Security.getKeyPair("server", "cs6238", "S3 Server");
            this.socket = new ServerSocket(port);
            if (this.serverKeys == null) {
                printError("Could not access server keys");
                System.exit(1);
            }
        } catch (IOException ioe) {
            printError("Could not bind to port " + port + ".");
            ioe.printStackTrace();
        } catch (GeneralSecurityException gse) {
            gse.printStackTrace();
        }
    }

    public void startServer() {
        printInfo("Started server on port " + this.socket.getLocalPort());
        Socket s;
        while (true) {
            try {
                s = socket.accept();
                InetSocketAddress remoteAddress = (InetSocketAddress) s.getRemoteSocketAddress();
                SSLSocket sslSocket = (SSLSocket) (socketFactory.createSocket(s, remoteAddress.getHostName(), s.getPort(), true));
                sslSocket.setUseClientMode(false);
                sslSocket.setNeedClientAuth(true);
                sslSocket.startHandshake();
                s = sslSocket;
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
