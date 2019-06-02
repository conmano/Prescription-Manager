package edu.uw.medhas.mhealthsecurityframework.storage.database.model;

/**
 * Created by medhasrivastava on 1/28/19.
 */

public class SecureString {
    private final String value;

    public SecureString(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
