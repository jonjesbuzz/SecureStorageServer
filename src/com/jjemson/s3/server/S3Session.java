package com.jjemson.s3.server;


import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;
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
        registry.add(DelegationRequest.dRequest);
        registry.add(DeleteRequest.delRequest);
        registry.add(DeleteResponse.delResponse);
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
                    S3FileManager.sharedInstance().checkInFile(this.user, cir);
                    CheckinResponse response = CheckinResponse.newBuilder().setSuccess(true).build();
                    S3Message respMsg = S3Message.newBuilder()
                            .setType(S3Message.MessageType.CheckinResponse)
                            .setExtension(CheckinResponse.ciResponse, response)
                            .build();
                    respMsg.writeDelimitedTo(this.socket.getOutputStream());
                }
                if (msg.getType() == S3Message.MessageType.CheckoutRequest) {
                    CheckoutRequest cor = msg.getExtension(CheckoutRequest.coRequest);
                    printInfo("Checkout:\n" + cor);
                    S3File file;
                    if (cor.hasOwner()) {
                        file = S3FileManager.sharedInstance().checkoutDelegatedFile(user, cor.getOwner(), cor);
                    } else {
                        file = S3FileManager.sharedInstance().checkoutFile(user, cor);
                    }
                    boolean successful = (file != null);
                    CheckoutResponse.Builder responseBuilder = CheckoutResponse.newBuilder().setSuccess(successful);
                    if (successful) {
                        responseBuilder.setFileData(ByteString.copyFrom(file.getFileData())).setSecurity(file.getFileSec());
                    }
                    CheckoutResponse response = responseBuilder.build();
                    printInfo("Response:\n" + response);
                    S3Message msg2 = S3Message.newBuilder()
                            .setType(S3Message.MessageType.CheckoutResponse)
                            .setExtension(CheckoutResponse.coResponse, response)
                            .build();
                    msg2.writeDelimitedTo(this.socket.getOutputStream());
                }
                if (msg.getType() == S3Message.MessageType.DelegationRequest) {
                    DelegationRequest delegationRequest = msg.getExtension(DelegationRequest.dRequest);
                    printInfo("Delegation request:\n" + delegationRequest);
                    S3FileManager.sharedInstance().addDelegation(delegationRequest.getDocumentId(), user, delegationRequest.getClientUser(), delegationRequest.getDuration(), delegationRequest.getPropagate());
                }
                if (msg.getType() == S3Message.MessageType.DeleteRequest) {
                    DeleteRequest deleteRequest = msg.getExtension(DeleteRequest.delRequest);
                    boolean success;
                    if (deleteRequest.hasDocumentOwner()) {
                        success = S3FileManager.sharedInstance().deleteFile(deleteRequest.getDocumentOwner(), deleteRequest.getDocumentId());
                    } else {
                        success = S3FileManager.sharedInstance().deleteFile(user, deleteRequest.getDocumentId());
                    }
                    DeleteResponse response = DeleteResponse.newBuilder()
                            .setSuccess(success)
                            .build();
                    S3Message msg2 = S3Message.newBuilder()
                            .setType(S3Message.MessageType.DeleteResponse)
                            .setExtension(DeleteResponse.delResponse, response)
                            .build();
                    msg2.writeDelimitedTo(this.socket.getOutputStream());

                }
            }
        } catch (IOException ioe) {
            printError("Error - Terminating session for user " + user + ".");
            ioe.printStackTrace();
        }
    }
}
