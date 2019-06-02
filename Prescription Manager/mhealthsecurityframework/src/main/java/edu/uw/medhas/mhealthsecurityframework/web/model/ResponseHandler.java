package edu.uw.medhas.mhealthsecurityframework.web.model;

/**
 * Created by medhas on 2/17/19.
 */

public interface ResponseHandler {
    void onSuccess(Response response);

    void onError(WebError webError);
}
