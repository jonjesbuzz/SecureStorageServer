package com.jjemson.s3.server;

import com.jjemson.s3.S3Protocol;

import java.util.Calendar;
import java.util.Date;
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
    private ConcurrentHashMap<String, S3FileDelegate> delegates;

    private S3FileManager() {
        metadata = new ConcurrentHashMap<>(50);
        delegates = new ConcurrentHashMap<>(50);
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
        S3FileDelegate delegate = delegates.get(fileID);
        if (delegate.expired()) {
            delegates.remove(fileID);
            return null;
        }
        return delegate.file;
    }

    public boolean addDelegation(String filename, String owner, String recipient, int duration, boolean propagation) {
        String fileID = S3File.documentID(owner, filename);
        String delegateID = S3File.documentID(owner, filename);

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, duration);
        Date expiration = calendar.getTime();

        S3File file = metadata.get(fileID);

        if (file == null) {
            S3FileDelegate delegate = delegates.get(delegateID);
            if (delegate == null) {
                return false;
            } else {
                if (delegate.expired()) {
                    delegates.remove(delegateID);
                    return false;
                }
                if (!delegate.propagate) {
                    return false;
                }
                if (expiration.after(delegate.expiry)) {
                    expiration = delegate.expiry;
                }
                delegates.put(delegateID, new S3FileDelegate(delegate.file, expiration, propagation));
            }
        } else {
            delegates.put(delegateID, new S3FileDelegate(file, expiration, propagation));
        }

        return true;
    }

    private class S3FileDelegate {
        private S3File file;
        private Date expiry;
        private boolean propagate;

        public S3FileDelegate(S3File file, Date expiry, boolean propagate) {
            this.file = file;
            this.expiry = expiry;
            this.propagate = propagate;
        }

        public boolean expired() {
            return new Date().after(expiry);
        }
    }
}
