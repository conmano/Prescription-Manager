package edu.uw.medhas.mhealthsecurityframework.storage.result;

/**
 * Created by medhas on 2/7/19.
 */

public class StorageResult<T> {
    private final T mResult;

    public StorageResult(T result) {
        mResult = result;
    }

    public T getResult() {
        return mResult;
    }
}
