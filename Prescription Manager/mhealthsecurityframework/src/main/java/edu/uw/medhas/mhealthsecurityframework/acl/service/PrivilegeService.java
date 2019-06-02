package edu.uw.medhas.mhealthsecurityframework.acl.service;

import edu.uw.medhas.mhealthsecurityframework.acl.db.ResultHandler;
import edu.uw.medhas.mhealthsecurityframework.acl.model.AuthContext;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Privilege;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;

/**
 * Created by medhas on 2/18/19.
 */

public interface PrivilegeService {

    void createPrivilege(final String roleName, final String resourceName, final String operationName,
                         final AuthContext authContext, final ResultHandler<Privilege> resultHandler);

    void deletePrivilege(final String roleName, final String resourceName, final String operationName,
                         final AuthContext authContext, final ResultHandler<Void> resultHandler);

    void isAllowed(final String userId, final String resourceName, final String operationName,
                   final ResultHandler<Boolean> resultHandler);

    void deleteResource(final String resourceName, final AuthContext authContext, final ResultHandler<Void> resultHandler);

    void deleteOperation(final String operationName, final AuthContext authContext, final ResultHandler<Void> resultHandler);
}
