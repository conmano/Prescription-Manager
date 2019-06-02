package edu.uw.medhas.mhealthsecurityframework.acl.dao;

import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Delete;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.OnConflictStrategy;
import android.arch.persistence.room.Query;
import android.arch.persistence.room.Update;

import edu.uw.medhas.mhealthsecurityframework.acl.model.Resource;

/**
 * Created by medhas on 2/18/19.
 */
@Dao
public interface ResourceDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    long insert(Resource resource);

    @Query("SELECT * FROM resources WHERE id = :id")
    Resource fetchOne(long id);

    @Query("SELECT * FROM resources WHERE name = :name")
    Resource fetchByName(String name);

    @Update
    void update(Resource resource);

    @Delete
    void delete(Resource resource);
}
