package com.jjemson.s3.server;

import com.jjemson.s3.S3Protocol.*;

import java.io.File;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * S3File
 *
 * @author Jonathan Jemson
 * @version 1.0
 */
class S3File {
    private String owner;
    private String filename;
    private Security fileSec;
    private Map<String, S3FileDelegate> delegates;

    private File file;

    protected S3File(String owner, String filename, Security fileSec) {
        this.owner = owner;
        this.filename = filename;
        this.fileSec = fileSec;
        this.file = new File(this.getDocumentID());
        this.delegates = new HashMap<>();
    }

    protected S3File(String owner, CheckinRequest checkIn) {
        this(owner, checkIn.getDocumentId(), checkIn.getSecurity());
    }

    public String getDocumentID() {
        return owner + "-" + filename;
    }

    public void delegate(String user, int timeInterval, boolean propagate) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, timeInterval);
        delegates.put(user, new S3FileDelegate(user, calendar.getTime(),  propagate));
    }

    private static class S3FileDelegate {
        private String user;
        private Date validUntil;
        private boolean propagate;

        S3FileDelegate(String user, Date validUntil, boolean propagate) {
            this.user = user;
            this.validUntil = validUntil;
            this.propagate = propagate;
        }
    }
}
