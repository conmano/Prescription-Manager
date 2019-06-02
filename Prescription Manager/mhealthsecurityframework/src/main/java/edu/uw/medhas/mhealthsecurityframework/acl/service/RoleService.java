package edu.uw.medhas.mhealthsecurityframework.acl.service;

import edu.uw.medhas.mhealthsecurityframework.acl.db.ResultHandler;
import edu.uw.medhas.mhealthsecurityframework.acl.model.AuthContext;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;

/**
 * Created by medhas on 2/18/19.
 */

public interface RoleService {

    void createRole(final Role role, final AuthContext authContext, final ResultHandler<Role> resultHandler);

    void deleteRole(final String roleName, final AuthContext authContext, final ResultHandler<Void> resultHandler);
}
