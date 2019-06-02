package edu.uw.medhas.mhealthsecurityframework.acl.service.impl;

import android.util.Log;

import java.time.Instant;

import edu.uw.medhas.mhealthsecurityframework.acl.constants.DbConstants;
import edu.uw.medhas.mhealthsecurityframework.acl.db.AccessControlDb;
import edu.uw.medhas.mhealthsecurityframework.acl.db.DbError;
import edu.uw.medhas.mhealthsecurityframework.acl.db.ResultHandler;
import edu.uw.medhas.mhealthsecurityframework.acl.model.AuthContext;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;
import edu.uw.medhas.mhealthsecurityframework.acl.model.User;
import edu.uw.medhas.mhealthsecurityframework.acl.model.UserRole;
import edu.uw.medhas.mhealthsecurityframework.acl.service.PrivilegeService;
import edu.uw.medhas.mhealthsecurityframework.acl.service.UserService;

/**
 * Created by medhas on 2/20/19.
 */

public class UserServiceImpl implements UserService {
    private final AccessControlDb mAclDb;
    private final PrivilegeService mPrivilegeService;

    public UserServiceImpl(AccessControlDb aclDb) {
        mAclDb = aclDb;
        mPrivilegeService = new PrivilegeServiceImpl(aclDb);
    }

    @Override
    public void createUser(final User user, final AuthContext authContext, final ResultHandler<User> resultHandler) {
        mPrivilegeService.isAllowed(authContext.getUserId(), DbConstants.USER_RESOURCE, DbConstants.CREATE_OP,
                new ResultHandler<Boolean>() {
                    @Override
                    public void onSuccess(Boolean result) {
                        if (!result) {
                            resultHandler.onFailure(DbError.UNAUTHORIZED);
                            return;
                        }

                        try {
                            user.setCreated(Instant.now());
                            user.setUpdated(Instant.now());
                            user.setCreatedBy(authContext.getUserId());
                            user.setUpdatedBy(authContext.getUserId());

                            mAclDb.getUserDao().insert(user);

                            resultHandler.onSuccess(user);
                        } catch (RuntimeException rex) {
                            Log.e("UserServiceImpl/createUser", DbError.UNEXPECTED_ERROR.getMessage(), rex);
                            resultHandler.onFailure(DbError.UNEXPECTED_ERROR);
                        }
                    }

                    @Override
                    public void onFailure(DbError error) {
                        resultHandler.onFailure(error);
                    }
                }
        );
    }

    @Override
    public void assignRoleToUser(final String userId, final String roleName, final AuthContext authContext,
                                 final ResultHandler<UserRole> resultHandler) {
        mPrivilegeService.isAllowed(authContext.getUserId(), DbConstants.USER_RESOURCE, DbConstants.UPDATE_OP,
                new ResultHandler<Boolean>() {
                    @Override
                    public void onSuccess(Boolean result) {
                        if (!result) {
                            resultHandler.onFailure(DbError.UNAUTHORIZED);
                            return;
                        }

                        try {
                            final User user = mAclDb.getUserDao().fetchOne(userId);
                            if (user == null) {
                                resultHandler.onFailure(DbError.INVALID_USER);
                                return;
                            }

                            final Role role = mAclDb.getRoleDao().fetchByName(roleName);
                            if (role == null) {
                                resultHandler.onFailure(DbError.INVALID_ROLE);
                                return;
                            }

                            final UserRole userRole = new UserRole();
                            userRole.setUserId(userId);
                            userRole.setRoleId(role.getId());
                            userRole.setCreatedBy(authContext.getUserId());
                            userRole.setUpdatedBy(authContext.getUserId());

                            mAclDb.getUserRoleDao().insert(userRole);

                            resultHandler.onSuccess(userRole);
                        } catch (RuntimeException rex) {
                            Log.e("UserServiceImpl/assignRoleToUser", DbError.UNEXPECTED_ERROR.getMessage(), rex);
                            resultHandler.onFailure(DbError.UNEXPECTED_ERROR);
                        }
                    }

                    @Override
                    public void onFailure(DbError error) {
                        resultHandler.onFailure(error);
                    }
                }
        );
    }

    @Override
    public void deleteUser(final String userId, final AuthContext authContext, final ResultHandler<Void> resultHandler) {
        mPrivilegeService.isAllowed(authContext.getUserId(), DbConstants.USER_RESOURCE, DbConstants.DELETE_OP,
                new ResultHandler<Boolean>() {
                    @Override
                    public void onSuccess(Boolean result) {
                        if (!result) {
                            resultHandler.onFailure(DbError.UNAUTHORIZED);
                            return;
                        }

                        try {
                            final User user = mAclDb.getUserDao().fetchOne(userId);
                            if (user == null) {
                                resultHandler.onFailure(DbError.INVALID_USER);
                                return;
                            }

                            mAclDb.runInTransaction(new Runnable() {
                                @Override
                                public void run() {
                                    mAclDb.getUserRoleDao().deleteByUser(userId);
                                    mAclDb.getUserDao().delete(user);

                                    resultHandler.onSuccess(null);
                                }
                            });
                        } catch (RuntimeException rex) {
                            Log.e("UserServiceImpl/deleteUser", DbError.UNEXPECTED_ERROR.getMessage(), rex);
                            resultHandler.onFailure(DbError.UNEXPECTED_ERROR);
                        }
                    }

                    @Override
                    public void onFailure(DbError error) {
                        resultHandler.onFailure(error);
                    }
                }
        );
    }
}
