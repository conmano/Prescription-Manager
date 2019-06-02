package edu.uw.medhas.mhealthsecurityframework.acl.db;

/**
 * Created by medhas on 2/22/19.
 */

public enum DbError {
    UNEXPECTED_ERROR(800, "Unexpected error encountered while querying the access control database"),
    UNAUTHORIZED(801, "User isn't authorized to perform this action on the resource"),
    INVALID_USER(802, "The user id is invalid"),
    INVALID_ROLE(803, "The role name is invalid"),
    INVALID_RESOURCE(804, "The resource name is invalid"),
    INVALID_OPERATION(805, "The operation name is invalid");

    private final int mCode;
    private final String mMessage;

    DbError(int code, String message) {
        mCode = code;
        mMessage = message;
    }

    public int getCode() {
        return mCode;
    }

    public String getMessage() {
        return mMessage;
    }
}
