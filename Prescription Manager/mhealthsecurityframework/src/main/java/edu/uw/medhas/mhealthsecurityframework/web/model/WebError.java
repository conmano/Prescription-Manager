package edu.uw.medhas.mhealthsecurityframework.web.model;

/**
 * Created by medhas on 2/17/19.
 */

public class WebError extends Response {
    public enum CustomErrorType {
        SINGLE_REQUEST(800, "Only one request can be processed at a time"),
        MALFORMED_URL(801, "Url is malformed"),
        CANT_CONNECT(802, "WebError connecting to the url"),
        NOT_SSL_URL(803, "Can't connect to non-SSL/TLS resources"),
        REQUEST_METHOD_NOT_SUPPORTED(804, "Request method not supported"),
        CANT_CONNECT_SSL(805, "WebError making SSL connection"),
        CANT_READ_RESPONSE(806, "WebError reading response"),
        NO_INTERNET_CONN(807, "Can't connect to the web"),
        CANT_SUBMIT_REQUEST(808, "WebError submitting request");

        private final int mCode;
        private final String mMessage;

        CustomErrorType(int code, String message) {
            mCode = code;
            mMessage = message;
        }
    }

    public WebError(int responseCode, byte[] body) {
        super(responseCode, body);
    }

    public WebError(CustomErrorType errorType) {
        super(errorType.mCode, errorType.mMessage);
    }
}
