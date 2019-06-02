package edu.uw.medhas.mhealthsecurityframework.acl.dao;

import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Delete;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.OnConflictStrategy;
import android.arch.persistence.room.Query;

import edu.uw.medhas.mhealthsecurityframework.acl.model.Privilege;

/**
 * Created by medhas on 2/18/19.
 */
@Dao
public interface PrivilegeDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    long insert(Privilege privilege);

    @Delete
    void delete(Privilege privilege);

    @Query("Delete from privileges where role_id = :roleId")
    void deleteByRole(long roleId);

    @Query("Delete from privileges where resource_id = :resourceId")
    void deleteByResource(long resourceId);

    @Query("Delete from privileges where operation_id = :operationId")
    void deleteByOperation(long operationId);

    @Query("SELECT COUNT(*) FROM privileges p" +
            " JOIN resources rs" +
            " ON rs.id = p.resource_id" +
            " JOIN operations o" +
            " ON o.id = p.operation_id" +
            " JOIN roles r" +
            " ON r.id = p.role_id" +
            " JOIN user_role ur" +
            " ON ur.role_id = r.id" +
            " JOIN users u" +
            " ON u.id = ur.user_id" +
            " WHERE u.id = :userId" +
            " AND rs.name = :resourceName" +
            " AND o.name = :operationName")
    int checkPermission(String userId, String resourceName, String operationName);
}
