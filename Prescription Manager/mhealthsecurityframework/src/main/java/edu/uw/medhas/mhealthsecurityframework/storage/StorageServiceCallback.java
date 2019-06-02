package edu.uw.medhas.mhealthsecurityframework.storage;

import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * Created by medhas on 2/7/19.
 */

public interface StorageServiceCallback<T> extends AuthenticationServiceCallback {
    void onSuccess(T result);

    void onFailure(StorageResultErrorType storageResultErrorType);
}
