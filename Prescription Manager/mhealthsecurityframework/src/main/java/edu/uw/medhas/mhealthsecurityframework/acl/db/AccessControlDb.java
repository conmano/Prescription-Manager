package edu.uw.medhas.mhealthsecurityframework.acl.db;

import android.arch.persistence.room.Database;
import android.arch.persistence.room.RoomDatabase;
import android.arch.persistence.room.TypeConverters;

import edu.uw.medhas.mhealthsecurityframework.acl.converter.InstantConverter;
import edu.uw.medhas.mhealthsecurityframework.acl.dao.OperationDao;
import edu.uw.medhas.mhealthsecurityframework.acl.dao.PrivilegeDao;
import edu.uw.medhas.mhealthsecurityframework.acl.dao.ResourceDao;
import edu.uw.medhas.mhealthsecurityframework.acl.dao.RoleDao;
import edu.uw.medhas.mhealthsecurityframework.acl.dao.UserDao;
import edu.uw.medhas.mhealthsecurityframework.acl.dao.UserRoleDao;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Operation;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Privilege;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Resource;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;
import edu.uw.medhas.mhealthsecurityframework.acl.model.User;
import edu.uw.medhas.mhealthsecurityframework.acl.model.UserRole;

/**
 * Created by medhas on 2/18/19.
 */

@Database(entities = {
            Operation.class,
            Resource.class,
            Role.class,
            User.class,
            UserRole.class,
            Privilege.class
        }, version = 3, exportSchema = false)
@TypeConverters({InstantConverter.class})
public abstract class AccessControlDb extends RoomDatabase {
    public abstract OperationDao getOperationDao();

    public abstract PrivilegeDao getPrivilegeDao();

    public abstract ResourceDao getResourceDao();

    public abstract RoleDao getRoleDao();

    public abstract UserDao getUserDao();

    public abstract UserRoleDao getUserRoleDao();
}
