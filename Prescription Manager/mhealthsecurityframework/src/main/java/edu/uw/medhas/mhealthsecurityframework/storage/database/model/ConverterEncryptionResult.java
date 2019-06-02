package edu.uw.medhas.mhealthsecurityframework.storage.database.model;

import java.util.Optional;

import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * Created by medhas on 2/9/19.
 */

public class ConverterEncryptionResult {
    private byte[] mResult;
    private StorageResultErrorType mErrorType = null;

    public void setResult(byte[] result) {
        mResult = result;
    }

    public byte[] getResult() {
        return mResult;
    }

    public Optional<StorageResultErrorType> getErrorType() {
        return Optional.ofNullable(mErrorType);
    }

    public void setErrorType(StorageResultErrorType errorType) {
        mErrorType = errorType;
    }
}
