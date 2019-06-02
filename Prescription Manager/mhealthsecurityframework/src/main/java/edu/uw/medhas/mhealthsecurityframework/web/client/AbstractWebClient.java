package edu.uw.medhas.mhealthsecurityframework.web.client;

import android.os.AsyncTask;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;

import edu.uw.medhas.mhealthsecurityframework.web.exception.NotSSLException;
import edu.uw.medhas.mhealthsecurityframework.web.model.Request;
import edu.uw.medhas.mhealthsecurityframework.web.model.RequestMethod;
import edu.uw.medhas.mhealthsecurityframework.web.model.Response;
import edu.uw.medhas.mhealthsecurityframework.web.model.WebError;
import edu.uw.medhas.mhealthsecurityframework.web.model.ResponseHandler;

/**
 * Created by medhas on 2/12/19.
 */

public abstract class AbstractWebClient extends AsyncTask<Request, Void, Response> {

    private static final int DEFAULT_CONNECTION_TIMEOUT = 120;
    private static final int DEFAULT_SOCKET_TIMEOUT = 120;

    private final int mConnectionTimeout;
    private final int mSocketTimeout;

    private final ResponseHandler mResponseHandler;

    protected AbstractWebClient(ResponseHandler responseHandler) {
        this(responseHandler, DEFAULT_CONNECTION_TIMEOUT, DEFAULT_SOCKET_TIMEOUT);
    }

    protected AbstractWebClient(ResponseHandler responseHandler, int connectionTimeout, int socketTimeout) {
        mConnectionTimeout = connectionTimeout;
        mSocketTimeout = socketTimeout;
        mResponseHandler = responseHandler;
    }

    protected abstract String getUserAgent();

    @Override
    protected void onPostExecute(Response response) {
        super.onPostExecute(response);

        if (response instanceof WebError) {
            mResponseHandler.onError((WebError) response);
        } else {
            mResponseHandler.onSuccess(response);
        }
    }

    @Override
    protected Response doInBackground(Request... requests) {
        if (requests.length > 1) {
            return new WebError(WebError.CustomErrorType.SINGLE_REQUEST);
        }

        final Request request = requests[0];

        Response response = null;

        if (RequestMethod.GET == request.getRequestMethod()) {
            response = doGet(request);
        } else if (RequestMethod.POST == request.getRequestMethod()) {
            response = doPost(request);
        } else if (RequestMethod.PUT == request.getRequestMethod()) {
            response = doPut(request);
        }

        return response;
    }

    private HttpsURLConnection getConnection(String urlStr) throws IOException {
        final URL url = new URL(urlStr);
        URLConnection connection = url.openConnection();

        if (!(connection instanceof HttpsURLConnection)) {
            throw new NotSSLException();
        }

        HttpsURLConnection httpsURLConnection = (HttpsURLConnection) connection;

        httpsURLConnection.setConnectTimeout(mConnectionTimeout * 1000);
        httpsURLConnection.setReadTimeout(mSocketTimeout * 1000);

        return httpsURLConnection;
    }

    private void buildHeaders(HttpsURLConnection httpsURLConnection, Map<String, String> headers) {
        httpsURLConnection.addRequestProperty("User-Agent", getUserAgent());
        for (String headerName : headers.keySet()) {
            httpsURLConnection.addRequestProperty(headerName, headers.get(headerName));
        }
    }

    private byte[] readResponse(HttpsURLConnection connection) throws IOException {
        try (final InputStream is = new BufferedInputStream(connection.getInputStream());
             final BufferedReader br = new BufferedReader(new InputStreamReader(is));) {

            String inputLine = null;
            final StringBuffer sb = new StringBuffer();

            while ((inputLine = br.readLine()) != null) {
                sb.append(inputLine);
            }

            return sb.toString().getBytes(StandardCharsets.UTF_8);
        }
    }

    private void writeRequest(HttpsURLConnection connection, byte[] content) throws IOException {
        try (final DataOutputStream output = new DataOutputStream(connection.getOutputStream())) {
            output.write(content);
        }
    }

    private Response doGet(Request request) {
        final HttpsURLConnection connection;
        try {
            connection = getConnection(request.getUrl());
        } catch (IOException e) {
            Log.e("AbstractWebClient::doGet",
                    "Can't create connection", e);

            if (e instanceof MalformedURLException) {
                return new WebError(WebError.CustomErrorType.MALFORMED_URL);
            }

            return new WebError(WebError.CustomErrorType.CANT_CONNECT);
        } catch (NotSSLException e) {
            Log.e("AbstractWebClient::doGet",
                    "Not SSL URL", e);
            return new WebError(WebError.CustomErrorType.NOT_SSL_URL);
        }

        buildHeaders(connection, request.getHeaders());

        try {
            connection.setRequestMethod(request.getRequestMethod().name());
        } catch (ProtocolException e) {
            Log.e("AbstractWebClient::doGet",
                    "Incorrect Request method", e);
            return new WebError(WebError.CustomErrorType.REQUEST_METHOD_NOT_SUPPORTED);
        }

        connection.setDoInput(true);

        final byte[] response;
        final int responseCode;
        try {
            responseCode = connection.getResponseCode();
            response = readResponse(connection);
        } catch (IOException  e) {
            Log.e("AbstractWebClient::doGet",
                    "WebError reading response", e);

            if (e instanceof SSLHandshakeException) {
                return new WebError(WebError.CustomErrorType.CANT_CONNECT_SSL);
            }

            return new WebError(WebError.CustomErrorType.CANT_READ_RESPONSE);
        } catch (SecurityException e) {
            Log.e("AbstractWebClient::doGet",
                    "WebError connecting to the internet", e);
            return new WebError(WebError.CustomErrorType.NO_INTERNET_CONN);
        }

        connection.disconnect();

        return (responseCode >= 400)
                ? new WebError(responseCode, response)
                : new Response(responseCode, response);
    }

    private Response doPut(Request request) {
        return doPost(request);
    }

    private Response doPost(Request request) {
        final HttpsURLConnection connection;
        try {
            connection = getConnection(request.getUrl());
        } catch (IOException e) {
            Log.e("AbstractWebClient::doPost",
                    "Can't create connection", e);
            if (e instanceof MalformedURLException) {
                return new WebError(WebError.CustomErrorType.MALFORMED_URL);
            }
            return new WebError(WebError.CustomErrorType.CANT_CONNECT);
        } catch (NotSSLException e) {
            Log.e("AbstractWebClient::doPost",
                    "Not SSL URL", e);
            return new WebError(WebError.CustomErrorType.NOT_SSL_URL);
        }

        buildHeaders(connection, request.getHeaders());

        try {
            connection.setRequestMethod(request.getRequestMethod().name());
        } catch (ProtocolException e) {
            Log.e("AbstractWebClient::doPost",
                    "Incorrect Request method", e);
            return new WebError(WebError.CustomErrorType.REQUEST_METHOD_NOT_SUPPORTED);
        }

        connection.setDoInput(true);
        connection.setDoOutput(true);

        try {
            writeRequest(connection, request.getBody());
        } catch (IOException e) {
            Log.e("AbstractWebClient::doPost",
                    "WebError submitting request", e);
            return new WebError(WebError.CustomErrorType.CANT_SUBMIT_REQUEST);
        }

        final byte[] response;
        final int responseCode;
        try {
            responseCode = connection.getResponseCode();
            response = readResponse(connection);
        } catch (IOException  e) {
            Log.e("AbstractWebClient::doPost",
                    "WebError reading response", e);

            if (e instanceof SSLHandshakeException) {
                return new WebError(WebError.CustomErrorType.CANT_CONNECT_SSL);
            }

            return new WebError(WebError.CustomErrorType.CANT_READ_RESPONSE);
        } catch (SecurityException e) {
            Log.e("AbstractWebClient::doPost",
                    "WebError connecting to the internet", e);
            return new WebError(WebError.CustomErrorType.NO_INTERNET_CONN);
        }

        connection.disconnect();

        return (responseCode >= 400)
                ? new WebError(responseCode, response)
                : new Response(responseCode, response);
    }
}
