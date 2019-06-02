package edu.uw.medhas.mhealthsecurityframework.acl.dao;

import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Delete;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.OnConflictStrategy;
import android.arch.persistence.room.Query;
import android.arch.persistence.room.Update;

import edu.uw.medhas.mhealthsecurityframework.acl.model.Operation;

/**
 * Created by medhas on 2/18/19.
 */
@Dao
public interface OperationDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    long insert(Operation operation);

    @Query("SELECT * FROM operations WHERE id = :id")
    Operation fetchOne(long id);

    @Query("SELECT * FROM operations WHERE name = :name")
    Operation fetchByName(String name);

    @Update
    void update (Operation operation);

    @Delete
    void delete (Operation operation);
}
