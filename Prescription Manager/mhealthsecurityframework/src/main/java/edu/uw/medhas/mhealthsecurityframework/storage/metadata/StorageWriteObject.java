package edu.uw.medhas.mhealthsecurityframework.storage.metadata;

import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureFile;

/**
 * Created by medhas on 2/8/19.
 */

public class StorageWriteObject<T> {
    private final SecureFile mSecureFile;
    private final T mObject;

    public StorageWriteObject(String fileName, T object) {
        mSecureFile = new SecureFile(fileName);
        mObject = object;
    }

    public SecureFile getSecureFile() {
        return mSecureFile;
    }

    public T getObject() {
        return mObject;
    }
}
