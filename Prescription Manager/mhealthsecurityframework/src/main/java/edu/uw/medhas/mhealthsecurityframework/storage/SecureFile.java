package edu.uw.medhas.mhealthsecurityframework.storage;

/**
 * Created by medhas on 5/31/18.
 */

public class SecureFile {
    private String mFilename;
    private boolean mIsJsonData;
    private boolean mIsEncryptedData;

    public String getFilename() {
        return mFilename;
    }

    public String getFinalFilename() {
        final StringBuilder sb = new StringBuilder(mFilename);
        if (isJsonData()) {
            sb.append(StorageConstants.sJsonExtension);
        }
        if (isEncryptedData()) {
            sb.append(StorageConstants.sEncryptedExtension);
        }
        return sb.toString();
    }

    public String getJsonEncryptedFileName() {
        return new StringBuilder(mFilename)
                .append(StorageConstants.sJsonExtension)
                .append(StorageConstants.sEncryptedExtension)
                .toString();
    }

    public String getJsonFileName() {
        return new StringBuilder(mFilename)
                .append(StorageConstants.sJsonExtension)
                .toString();
    }

    public String getEncryptedFileName() {
        return new StringBuilder(mFilename)
                .append(StorageConstants.sEncryptedExtension)
                .toString();
    }

    public void setFilename(String filename) {
        mFilename = filename;
    }

    public boolean isJsonData() {
        return mIsJsonData;
    }

    public void setJsonData(boolean isJsonData) {
        mIsJsonData = isJsonData;
    }

    public boolean isEncryptedData() {
        return mIsEncryptedData;
    }

    public void setEncryptedData(boolean isEncryptedData) {
        mIsEncryptedData = isEncryptedData;
    }
}
