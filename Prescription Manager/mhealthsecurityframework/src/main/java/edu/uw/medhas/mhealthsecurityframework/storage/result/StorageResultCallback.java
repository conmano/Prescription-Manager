package edu.uw.medhas.mhealthsecurityframework.storage.result;

import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationServiceCallback;

/**
 * Created by medhas on 2/7/19.
 */

public interface StorageResultCallback<T> extends AuthenticationServiceCallback {
    void onSuccess(StorageResult<T> storageResult);

    void onFailure(StorageResultErrorType errorType);
}
