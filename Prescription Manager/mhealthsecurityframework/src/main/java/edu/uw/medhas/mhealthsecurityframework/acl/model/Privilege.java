package edu.uw.medhas.mhealthsecurityframework.acl.model;

import android.arch.persistence.room.ColumnInfo;
import android.arch.persistence.room.Entity;
import android.support.annotation.NonNull;

import java.time.Instant;

/**
 * Created by medhas on 2/18/19.
 */

@Entity(tableName = "privileges", primaryKeys = {"role_id", "resource_id", "operation_id"})
public class Privilege extends AbstractAuditModel {
    @NonNull
    @ColumnInfo(name = "role_id")
    private long mRoleId;

    @NonNull
    @ColumnInfo(name = "resource_id")
    private long mResourceId;

    @NonNull
    @ColumnInfo(name = "operation_id")
    private long mOperationId;

    @NonNull
    public long getRoleId() {
        return mRoleId;
    }

    public void setRoleId(@NonNull long roleId) {
        mRoleId = roleId;
    }

    @NonNull
    public long getResourceId() {
        return mResourceId;
    }

    public void setResourceId(@NonNull long resourceId) {
        mResourceId = resourceId;
    }

    @NonNull
    public long getOperationId() {
        return mOperationId;
    }

    public void setOperationId(@NonNull long operationId) {
        mOperationId = operationId;
    }
}
