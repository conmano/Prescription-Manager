package edu.uw.medhas.mhealthsecurityframework.model.secureDatabaseModel.entity;

import android.arch.persistence.room.*;

import java.util.List;

/**
 * Created by medhasrivastava on 1/23/19.
 */

@Dao
public interface DaoAccess {
    @Insert
    long insertSingle (SensitiveDbData object);

    @Insert
    void insertMultiple (List<SensitiveDbData> objectList);

    @Query ("SELECT * FROM sensitive_db_data WHERE id = :id")
    SensitiveDbData fetchOnebyId (int id);

    @Update
    void update (SensitiveDbData object);

    @Delete
    void delete (SensitiveDbData object);
}
