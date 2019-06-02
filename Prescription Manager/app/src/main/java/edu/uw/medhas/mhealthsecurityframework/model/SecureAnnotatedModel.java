package edu.uw.medhas.mhealthsecurityframework.model;

import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureData;

/**
 * Created by medhas on 5/29/18.
 */

@SecureData
public class SecureAnnotatedModel {
    private String mData;

    public void setData(String data) {
        mData = data;
    }

    public String getData() {
        return mData;
    }
}
