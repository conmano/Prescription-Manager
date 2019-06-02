package edu.uw.medhas.mhealthsecurityframework.storage.database.converters;

/**
 * Created by medhasrivastava on 1/29/19.
 */

public abstract class AbstractSecureConverter {
    protected String getKeyAlias() {
        return "mhealth-security-framework-database-storage";
    }
}
