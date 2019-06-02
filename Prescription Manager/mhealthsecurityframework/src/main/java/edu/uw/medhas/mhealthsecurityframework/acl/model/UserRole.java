package edu.uw.medhas.mhealthsecurityframework.acl.model;

import android.arch.persistence.room.ColumnInfo;
import android.arch.persistence.room.Entity;
import android.support.annotation.NonNull;

import java.time.Instant;

/**
 * Created by medhas on 2/18/19.
 */

@Entity(tableName = "user_role", primaryKeys = {"user_id", "role_id"})
public class UserRole extends AbstractAuditModel {
    @NonNull
    @ColumnInfo(name = "user_id")
    private String mUserId;

    @NonNull
    @ColumnInfo(name = "role_id")
    private long mRoleId;

    @NonNull
    public String getUserId() {
        return mUserId;
    }

    public void setUserId(@NonNull String userId) {
        mUserId = userId;
    }

    @NonNull
    public long getRoleId() {
        return mRoleId;
    }

    public void setRoleId(@NonNull long roleId) {
        mRoleId = roleId;
    }
}
