package edu.uw.medhas.mhealthsecurityframework.acl.service;

import android.arch.persistence.db.SupportSQLiteDatabase;
import android.arch.persistence.room.Room;
import android.arch.persistence.room.RoomDatabase;
import android.content.ContentValues;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.support.annotation.NonNull;
import android.util.Log;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

import edu.uw.medhas.mhealthsecurityframework.acl.constants.DbConstants;
import edu.uw.medhas.mhealthsecurityframework.acl.db.AccessControlDb;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Operation;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Privilege;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Resource;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;
import edu.uw.medhas.mhealthsecurityframework.acl.model.User;
import edu.uw.medhas.mhealthsecurityframework.acl.service.impl.PrivilegeServiceImpl;
import edu.uw.medhas.mhealthsecurityframework.acl.service.impl.RoleServiceImpl;
import edu.uw.medhas.mhealthsecurityframework.acl.service.impl.UserServiceImpl;

/**
 * Created by medhas on 2/20/19.
 */

public class AclServiceFactory {
    private static AclServiceFactory INSTANCE = null;

    private final AccessControlDb mAclDb;

    private AclServiceFactory(Context context) {
        mAclDb = Room.databaseBuilder(context, AccessControlDb.class, DbConstants.DB_NAME)
                .allowMainThreadQueries()
                .fallbackToDestructiveMigration()
                .addCallback(new RoomDatabase.Callback() {
                    @Override
                    public void onCreate(@NonNull SupportSQLiteDatabase db) {
                        super.onCreate(db);
                        Log.i("AclServiceFactory", "Going to pre-poulate data");

                        final String userId = DbConstants.ROOT_USER_ID;

                        final ContentValues userValues = new ContentValues();
                        userValues.put("id", userId);
                        userValues.put("name", DbConstants.ROOT_USER_NAME);

                        insertPrepopulationData(db, "users", userValues);

                        final ContentValues roleValues = new ContentValues();
                        roleValues.put("name", DbConstants.SUPERUSER_ROLE);

                        long roleId = insertPrepopulationData(db, "roles", roleValues);

                        final ContentValues userRoleValues = new ContentValues();
                        userRoleValues.put("user_id", userId);
                        userRoleValues.put("role_id", roleId);
                        insertPrepopulationData(db, "user_role", userRoleValues);

                        // Create all operations
                        final List<Long> ops = new ArrayList<>();
                        ops.add(createOperation(db, DbConstants.CREATE_OP));
                        ops.add(createOperation(db, DbConstants.READ_OP));
                        ops.add(createOperation(db, DbConstants.UPDATE_OP));
                        ops.add(createOperation(db, DbConstants.DELETE_OP));

                        // Create all privileges
                        createPrivilege(db, roleId, DbConstants.USER_RESOURCE, ops);
                        createPrivilege(db, roleId, DbConstants.ROLE_RESOURCE, ops);
                        createPrivilege(db, roleId, DbConstants.PRIVILEGE_RESOURCE, ops);

                        Log.i("AclServiceFactory", "Data pre-population complete");
                    }
                })
                .build();

        // Trigger DB Creation
        mAclDb.query("select 1", null);
    }

    private long insertPrepopulationData(SupportSQLiteDatabase db, String tableName, ContentValues values) {
        values.put("created", Instant.now().getEpochSecond());
        values.put("created_by", DbConstants.ROOT_USER_ID);
        values.put("updated", Instant.now().getEpochSecond());
        values.put("updated_by", DbConstants.ROOT_USER_ID);

        return db.insert(tableName, SQLiteDatabase.CONFLICT_REPLACE, values);
    }

    private long createOperation(SupportSQLiteDatabase db, String opName) {
        final ContentValues opValues = new ContentValues();
        opValues.put("name", opName);

        return insertPrepopulationData(db, "operations", opValues);
    }

    private void createPrivilege(SupportSQLiteDatabase db, long roleId, String resourceName, List<Long> ops) {
        final ContentValues resValues = new ContentValues();
        resValues.put("name", resourceName);

        final long resId = insertPrepopulationData(db, "resources", resValues);

        for (Long opId : ops) {
            final ContentValues privilegeValues = new ContentValues();
            privilegeValues.put("role_id", roleId);
            privilegeValues.put("resource_id", resId);
            privilegeValues.put("operation_id", opId);

            insertPrepopulationData(db, "privileges", privilegeValues);
        }
    }

    public static void init(Context context) {
        if (INSTANCE == null) {
            INSTANCE = new AclServiceFactory(context);
        }
    }

    public static AclServiceFactory getInstance() {
        return INSTANCE;
    }

    public UserService getUserService() {
        return new UserServiceImpl(mAclDb);
    }

    public RoleService getRoleService() {
        return new RoleServiceImpl(mAclDb);
    }

    public PrivilegeService getPrivilegeService() {
        return new PrivilegeServiceImpl(mAclDb);
    }
}
