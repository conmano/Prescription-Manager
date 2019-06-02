package edu.uw.medhas.mhealthsecurityframework.webclient;

import edu.uw.medhas.mhealthsecurityframework.web.client.AbstractWebClient;
import edu.uw.medhas.mhealthsecurityframework.web.model.ResponseHandler;

/**
 * Created by medhas on 2/15/19.
 */

public class TestWebClient extends AbstractWebClient {
    public TestWebClient(ResponseHandler responseHandler) {
        super(responseHandler);
    }

    @Override
    protected String getUserAgent() {
        return "Test Web Client";
    }
}
