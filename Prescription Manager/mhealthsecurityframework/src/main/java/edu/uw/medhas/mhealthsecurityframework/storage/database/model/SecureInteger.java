package edu.uw.medhas.mhealthsecurityframework.storage.database.model;

/**
 * Created by medhasrivastava on 1/28/19.
 */

public class SecureInteger {
    private final Integer value;

    public SecureInteger(Integer value) {
        this.value = value;
    }

    public Integer getValue() {
        return value;
    }
}
