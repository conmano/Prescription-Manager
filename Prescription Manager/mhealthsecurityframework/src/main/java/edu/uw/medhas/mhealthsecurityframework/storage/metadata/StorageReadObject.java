package edu.uw.medhas.mhealthsecurityframework.storage.metadata;

import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureFile;

/**
 * Created by medhas on 2/8/19.
 */

public class StorageReadObject<T> {
    private final SecureFile mSecureFile;
    private final Class<T> mClazz;
    private byte[] mObjectBytes;

    public StorageReadObject(String fileName, Class<T> clazz) {
        mSecureFile = new SecureFile(fileName);
        mClazz = clazz;
    }

    public SecureFile getSecureFile() {
        return mSecureFile;
    }

    public Class<T> getClazz() {
        return mClazz;
    }

    public byte[] getObjectBytes() {
        return mObjectBytes;
    }

    public void setObjectBytes(byte[] objectBytes) {
        mObjectBytes = objectBytes;
    }
}
