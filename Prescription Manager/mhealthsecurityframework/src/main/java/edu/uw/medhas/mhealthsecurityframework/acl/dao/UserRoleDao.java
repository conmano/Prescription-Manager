package edu.uw.medhas.mhealthsecurityframework.acl.dao;

import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Delete;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.OnConflictStrategy;
import android.arch.persistence.room.Query;

import edu.uw.medhas.mhealthsecurityframework.acl.model.Privilege;
import edu.uw.medhas.mhealthsecurityframework.acl.model.UserRole;

/**
 * Created by medhas on 2/18/19.
 */
@Dao
public interface UserRoleDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    long insert(UserRole userRole);

    @Delete
    void delete(UserRole userRole);

    @Query("Delete from user_role where user_id = :userId")
    void deleteByUser(String userId);

    @Query("Delete from user_role where role_id = :roleId")
    void deleteByRole(long roleId);
}
