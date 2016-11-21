package com.jjemson.s3.server;


import com.google.protobuf.ExtensionRegistry;
import com.jjemson.s3.S3Protocol.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

/**
 * S3Session
 *
 * @author Jonathan Jemson
 * @version 1.0
 */
class S3Session implements Runnable {

    private Socket socket;
    private String user;

    private static ExtensionRegistry registry = ExtensionRegistry.newInstance();

    static {
        registry.add(CheckinRequest.ciRequest);
        registry.add(CheckinResponse.ciResponse);
        registry.add(CheckoutResponse.coResponse);
        registry.add(CheckoutRequest.coRequest);
        registry.add(Login.login);
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

    public S3Session(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            while (true) {
                InputStream ios = this.socket.getInputStream();
                S3Message msg = S3Message.parseDelimitedFrom(ios, registry);

                // If there is no message, just wait for a new message.
                if (msg == null) continue;

                if (msg.getType() == S3Message.MessageType.Login) {
                    Login login = msg.getExtension(Login.login);
                    this.user = login.getUser();
                    printInfo("Login\n" + login);

                    // TODO Send your authentication.
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
