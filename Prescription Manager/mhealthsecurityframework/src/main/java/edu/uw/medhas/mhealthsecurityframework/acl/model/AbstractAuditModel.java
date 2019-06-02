package edu.uw.medhas.mhealthsecurityframework.acl.model;

import android.arch.persistence.room.ColumnInfo;

import java.time.Instant;

import edu.uw.medhas.mhealthsecurityframework.acl.constants.DbConstants;

/**
 * Created by medhas on 2/18/19.
 */

public abstract class AbstractAuditModel {
    @ColumnInfo(name = "created")
    private Instant mCreated = Instant.now();

    @ColumnInfo(name = "created_by")
    private String mCreatedBy = DbConstants.ROOT_USER_ID;

    @ColumnInfo(name = "updated")
    private Instant mUpdated = Instant.now();

    @ColumnInfo(name = "updated_by")
    private String mUpdatedBy = DbConstants.ROOT_USER_ID;

    public Instant getCreated() {
        return mCreated;
    }

    public void setCreated(Instant created) {
        mCreated = created;
    }

    public String getCreatedBy() {
        return mCreatedBy;
    }

    public void setCreatedBy(String createdBy) {
        mCreatedBy = createdBy;
    }

    public Instant getUpdated() {
        return mUpdated;
    }

    public void setUpdated(Instant updated) {
        mUpdated = updated;
    }

    public String getUpdatedBy() {
        return mUpdatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        mUpdatedBy = updatedBy;
    }
}
