package edu.uw.medhas.mhealthsecurityframework.storage.database.model;

/**
 * Created by medhasrivastava on 1/28/19.
 */

public class SecureFloat {
    private final Float value;

    public SecureFloat(Float value) {
        this.value = value;
    }

    public Float getValue() {
        return value;
    }
}
