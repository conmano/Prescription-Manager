package edu.uw.medhas.mhealthsecurityframework.acl.model;

import edu.uw.medhas.mhealthsecurityframework.acl.constants.DbConstants;

/**
 * Created by medhas on 2/18/19.
 */

public class AuthContext {
    private final String mUserId;

    public AuthContext(String userId) {
        mUserId = userId;
    }

    public static AuthContext getRootContext() {
        return new AuthContext(DbConstants.ROOT_USER_ID);
    }

    public String getUserId() {
        return mUserId;
    }
}
