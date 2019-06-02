package edu.uw.medhas.mhealthsecurityframework.storage.database.model;

/**
 * Created by medhasrivastava on 1/28/19.
 */

public class SecureLong {
    private final Long value;

    public SecureLong(Long value) {
        this.value = value;
    }

    public Long getValue() {
        return value;
    }
}
