package edu.uw.medhas.mhealthsecurityframework.web.model;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Created by medhas on 2/17/19.
 */

public class Response {
    private final int mResponseCode;
    private final byte[] mBody;

    public Response(byte[] body) {
        this(200, body);
    }

    public Response(String body) {
        this(200, body.getBytes(StandardCharsets.UTF_8));
    }

    public Response(int responseCode, String body) {
        this(responseCode, body.getBytes(StandardCharsets.UTF_8));
    }

    public Response(int responseCode, byte[] body) {
        mResponseCode = responseCode;
        mBody = body;
    }

    public int getResponseCode() {
        return mResponseCode;
    }

    public byte[] getBody() {
        return mBody;
    }

    @Override
    public String toString() {
        return "{responseCode:" + mResponseCode +
                ", mBody:{" + new String(mBody, StandardCharsets.UTF_8) +
                '}';
    }
}
