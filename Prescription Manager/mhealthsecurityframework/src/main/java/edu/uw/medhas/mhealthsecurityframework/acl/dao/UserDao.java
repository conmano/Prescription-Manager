package edu.uw.medhas.mhealthsecurityframework.acl.dao;

import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Delete;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.OnConflictStrategy;
import android.arch.persistence.room.Query;
import android.arch.persistence.room.Update;

import edu.uw.medhas.mhealthsecurityframework.acl.model.User;

/**
 * Created by medhas on 2/18/19.
 */
@Dao
public interface UserDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    void insert(User user);

    @Query("SELECT * FROM users WHERE id = :id")
    User fetchOne(String id);

    @Update
    void update(User user);

    @Delete
    void delete(User user);
}
