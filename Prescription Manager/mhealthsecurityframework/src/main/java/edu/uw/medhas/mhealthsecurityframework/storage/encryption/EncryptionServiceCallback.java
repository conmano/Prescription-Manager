package edu.uw.medhas.mhealthsecurityframework.storage.encryption;

import javax.crypto.Cipher;

import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * Created by medhas on 2/7/19.
 */

public interface EncryptionServiceCallback extends AuthenticationServiceCallback {
    void onSuccess(Cipher cipher);

    void onFailure(StorageResultErrorType storageResultErrorType);
}
