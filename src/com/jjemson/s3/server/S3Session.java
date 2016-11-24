package com.jjemson.s3.server;


import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.ByteString;
import com.jjemson.s3.S3Protocol.*;
import com.jjemson.s3.S3Security;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

/**
 * S3Session
 *
 * @author Jonathan Jemson
 * @version 1.0
 */
class S3Session implements Runnable {

    private Socket socket;
    private String user;
    private KeyPair serverKeys;

    private static ExtensionRegistry registry = ExtensionRegistry.newInstance();

    static {
        registry.add(CheckinRequest.ciRequest);
        registry.add(CheckinResponse.ciResponse);
        registry.add(CheckoutResponse.coResponse);
        registry.add(CheckoutRequest.coRequest);
        registry.add(LoginRequest.login);
        registry.add(LoginResponse.login);
    }

    private void printInfo(String s) {
        if (user == null) {
            System.out.println("[Session: (no user)] " + s);
        } else {
            System.out.println("[Session: " + user + "] " + s);
        }
    }
    private void printError(String s) {
        System.err.println("[Session] " + s);
    }

    public S3Session(Socket socket, KeyPair serverKeys) {
        this.socket = socket;
        this.serverKeys = serverKeys;
    }

    @Override
    public void run() {
        try {
            while (true) {
                InputStream ios = this.socket.getInputStream();
                S3Message msg = S3Message.parseDelimitedFrom(ios, registry);

                // If there is no message, just wait for a new message.
                if (msg == null) continue;

                if (msg.getType() == S3Message.MessageType.LoginRequest) {
                    LoginRequest login = msg.getExtension(LoginRequest.login);
                    this.user = login.getUser();
                    Certificate other = S3Security.reconstructEncodedCertificate(login.getClientCert().toByteArray());
                    if (other == null) {
                        printError("Could not reconstruct client's public key.");
                        return;
                    }
                    if (!S3Security.verifyCertificate("server", "cs6238", other)) {
                        printError("Could not verify certificate as coming from CA.");
                        return;
                    }
                    Certificate serverCert = S3Security.getCertificate("server", "cs6238", "S3 Server");
                    try {
                        LoginResponse response = LoginResponse.newBuilder()
                                .setServerCert(ByteString.copyFrom(serverCert.getEncoded()))
                                .build();
                        S3Message respMsg = S3Message.newBuilder()
                                .setType(S3Message.MessageType.LoginResponse)
                                .setExtension(LoginResponse.login, response)
                                .build();
                        respMsg.writeDelimitedTo(this.socket.getOutputStream());
                    } catch (CertificateEncodingException cee) {
                        printError("Could not encode certificate.");
                        this.socket.close();
                        return;
                    }

                }
                if (msg.getType() == S3Message.MessageType.CheckinRequest) {
                    CheckinRequest cir = msg.getExtension(CheckinRequest.ciRequest);
                    printInfo("CheckIn:\n" + cir);
                    S3FileManager.sharedInstance();
                }
            }
        } catch (IOException ioe) {
            printError("Error - Terminating session for user " + user + ".");
            ioe.printStackTrace();
        }
    }
}
