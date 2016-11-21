package com.jjemson.s3.server;

import java.util.concurrent.ConcurrentHashMap;

/**
 * S3FileManager
 *
 * @author Jonathan Jemson
 * @version 1.0
 */
class S3FileManager {

    private static S3FileManager instance;

    private ConcurrentHashMap<String, S3File> fileListing;

    private S3FileManager() {
        fileListing = new ConcurrentHashMap<>(50);
    }

    public static S3FileManager sharedInstance() {
        if (instance == null) {
            instance = new S3FileManager();
        }
        return instance;
    }

    public void updateFile(S3File file) {
        S3File f = fileListing.get(file.getDocumentID());
        if (f == null) {
            f = file;
        } else {
            // TODO Someone is updating an existing file.
            // Make sure they own the file or have access delegation.
        }
    }

    public void removeFile(String owner, String documentID) {
    }
}
