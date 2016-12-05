package com.jjemson.s3.server;

import com.jjemson.s3.S3Protocol;

import java.io.*;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * S3FileManager
 *
 * @author Jonathan Jemson
 * @version 1.0
 */
class S3FileManager implements Serializable {

    private static S3FileManager instance;

    private ConcurrentHashMap<String, S3File> metadata;
    private ConcurrentHashMap<String, Set<S3FileDelegate>> delegateLookup;

    private S3FileManager() {
        metadata = new ConcurrentHashMap<>(50);
        delegateLookup = new ConcurrentHashMap<>(10);
    }

    public static S3FileManager sharedInstance() {
        if (instance == null) {
            File file = new File(".s3meta");
            if (!file.exists()) {
                instance = new S3FileManager();
            } else {
                try {
                    FileInputStream fileInputStream = new FileInputStream(file);
                    ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
                    instance = (S3FileManager) objectInputStream.readObject();
                } catch (IOException ioe) {
                    instance = new S3FileManager();
                    ioe.printStackTrace();
                } catch (ClassNotFoundException cnfe) {
                    cnfe.printStackTrace();
                }
            }
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

    public S3File checkoutDelegatedFile(String me, S3Protocol.CheckoutRequest request) {
        if (request.getOwner().equals(me)) {
            return checkoutFile(me, request);
        }
        Set<S3FileDelegate> delegateSet = delegateLookup.get(me);
        if (delegateSet == null) {
            return null;
        }
        S3FileDelegate delegate = null;
        for (S3FileDelegate s3FileDelegate : delegateSet) {
            if (s3FileDelegate.file.getFilename().equals(request.getDocumentId())) {
                delegate = s3FileDelegate;
                break;
            }
        }
        if (delegate == null) {
            return null;
        }
        if (delegate.expired()) {
            delegateSet.remove(delegate);
            delegateLookup.put(me, delegateSet);
            return null;
        }
        return delegate.file;
    }

    public boolean addDelegation(String filename, String owner, String recipient, int duration, boolean propagation) {
        String fileID = S3File.documentID(owner, filename);
        LocalDateTime expiration = LocalDateTime.now().plusSeconds(duration);
        S3File file = metadata.get(fileID);

        Set<S3FileDelegate> delegateSet = delegateLookup.getOrDefault(owner, new HashSet<>());
        if (file == null) {
            S3FileDelegate del = null;
            for (S3FileDelegate delegate : delegateSet) {
                if (delegate.file.getFilename().equals(filename)) {
                    del = delegate;
                    break;
                }
            }
            if (del == null) {
                return false;
            }
            if (del.expired()) {
                delegateSet.remove(del);
                return false;
            }
            if (!del.propagate) {
                return false;
            }
            if (expiration.isAfter(del.expiry)) {
                expiration = del.expiry;
            }
            delegateSet.add(new S3FileDelegate(del.file, expiration, propagation));
            delegateLookup.put(recipient, delegateSet);
        } else {
            delegateSet.add(new S3FileDelegate(file, expiration, propagation));
            delegateLookup.put(recipient, delegateSet);
        }
        return true;
    }
}
class S3FileDelegate implements Serializable {
    S3File file;
    LocalDateTime expiry;
    boolean propagate;


    public S3FileDelegate(S3File file, LocalDateTime expiry, boolean propagate) {
        this.file = file;
        this.expiry = expiry;
        this.propagate = propagate;
    }

    public boolean expired() {
        return LocalDateTime.now().isAfter(expiry);
    }

    @Override
    public String toString() {
        return "File: " + file.toString() + "\n" +
                "Expires: " + expiry.toString() + "\n" +
                "Propagates? " + propagate;
    }
}
