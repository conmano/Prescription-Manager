package edu.uw.medhas.mhealthsecurityframework.storage.database.model;

/**
 * Created by medhasrivastava on 1/28/19.
 */

public class SecureDouble {
    private final Double value;

    public SecureDouble(Double value) {
        this.value = value;
    }

    public Double getValue() {
        return value;
    }
}
