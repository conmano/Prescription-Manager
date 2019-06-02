package edu.uw.medhas.mhealthsecurityframework.acl.db;

/**
 * Created by medhas on 2/22/19.
 */

public interface ResultHandler<T> {
    void onSuccess(T result);

    void onFailure(DbError error);
}
