package com.jjemson.s3.server;

import com.jjemson.s3.S3Protocol;

import java.util.concurrent.ConcurrentHashMap;

/**
 * S3FileManager
 *
 * @author Jonathan Jemson
 * @version 1.0
 */
class S3FileManager {

    private static S3FileManager instance;

    private ConcurrentHashMap<String, S3File> metadata;

    private S3FileManager() {
        metadata = new ConcurrentHashMap<>(50);
    }

    public static S3FileManager sharedInstance() {
        if (instance == null) {
            instance = new S3FileManager();
        }
        return instance;
    }

    public void checkInFile(String owner, S3Protocol.CheckinRequest request) {
        S3File file = new S3File(owner, request);
        metadata.put(file.getDocumentID(), file);
    }

    public S3File checkoutFile(String owner, S3Protocol.CheckoutRequest request) {
        String fileID = S3File.documentID(owner, request.getDocumentId());
        S3File file = metadata.get(fileID);
        return file;
    }

    public boolean deleteFile(String owner, String filename) {
        String fileID = S3File.documentID(owner, filename);
        S3File file = metadata.get(fileID);
        if (file == null) {
            return false;
        }
        file.delete();
        metadata.remove(fileID);
        return true;
    }

    public S3File checkoutDelegatedFile(String me, String owner, S3Protocol.CheckoutRequest request) {
        String fileID = S3File.documentID(owner, request.getDocumentId());
        S3File file = metadata.get(fileID);
        if (file.checkDelegateForUser(me)) {
            return file;
        }
        return null;
    }

    public boolean addDelegation(String filename, String owner, String recipient, int duration, boolean propagation) {
        String fileID = S3File.documentID(owner, filename);
        S3File file = metadata.get(fileID);
        if (file == null) {
            return false;
        }
        file.delegate(recipient, duration, propagation);
        return true;
    }
}
