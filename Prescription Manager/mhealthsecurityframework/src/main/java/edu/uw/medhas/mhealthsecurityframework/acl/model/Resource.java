package edu.uw.medhas.mhealthsecurityframework.acl.model;

import android.arch.persistence.room.ColumnInfo;
import android.arch.persistence.room.Entity;
import android.arch.persistence.room.Index;
import android.arch.persistence.room.PrimaryKey;
import android.support.annotation.NonNull;

import java.time.Instant;

/**
 * Created by medhas on 2/18/19.
 */

@Entity(tableName = "resources",
        indices = {@Index(name = "res_unique_name", value = "name", unique = true)})
public class Resource extends AbstractAuditModel {
    @NonNull
    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = "id")
    private long mId;

    @ColumnInfo(name = "name")
    private String mName;

    @NonNull
    public long getId() {
        return mId;
    }

    public void setId(@NonNull long id) {
        mId = id;
    }

    public String getName() {
        return mName;
    }

    public void setName(String name) {
        mName = name;
    }
}
