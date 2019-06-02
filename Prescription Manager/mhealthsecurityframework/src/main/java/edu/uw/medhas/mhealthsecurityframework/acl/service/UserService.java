package edu.uw.medhas.mhealthsecurityframework.acl.service;

import edu.uw.medhas.mhealthsecurityframework.acl.db.ResultHandler;
import edu.uw.medhas.mhealthsecurityframework.acl.model.AuthContext;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;
import edu.uw.medhas.mhealthsecurityframework.acl.model.User;
import edu.uw.medhas.mhealthsecurityframework.acl.model.UserRole;

/**
 * Created by medhas on 2/18/19.
 */

public interface UserService {

    void createUser(final User user, final AuthContext authContext, final ResultHandler<User> resultHandler);

    void assignRoleToUser(final String userId, final String roleName, final AuthContext authContext,
                          final ResultHandler<UserRole> resultHandler);

    void deleteUser(final String userId, final AuthContext authContext, final ResultHandler<Void> resultHandler);
}
