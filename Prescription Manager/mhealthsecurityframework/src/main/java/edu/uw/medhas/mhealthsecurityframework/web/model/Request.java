package edu.uw.medhas.mhealthsecurityframework.web.model;

import java.util.Collections;
import java.util.Map;

/**
 * Created by medhas on 2/17/19.
 */

public class Request {
    private final String mUrl;
    private final RequestMethod mRequestMethod;
    private final Map<String, String> mHeaders;
    private final byte[] mBody;

    public Request(String url, RequestMethod requestMethod, Map<String, String> headers, byte[] body) {
        mUrl = url;
        mRequestMethod = requestMethod;
        mHeaders = headers;
        mBody = body;
    }

    public Request(String url, RequestMethod requestMethod, Map<String, String> headers) {
        this(url, requestMethod, headers, null);
    }

    public Request(String url, RequestMethod requestMethod) {
        this(url, requestMethod, Collections.<String, String>emptyMap(), null);
    }

    public String getUrl() {
        return mUrl;
    }

    public RequestMethod getRequestMethod() {
        return mRequestMethod;
    }

    public Map<String, String> getHeaders() {
        return mHeaders;
    }

    public byte[] getBody() {
        return mBody;
    }
}
