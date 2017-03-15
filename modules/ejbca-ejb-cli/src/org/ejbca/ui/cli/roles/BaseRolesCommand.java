/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.cli.roles;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.authentication.cli.CliUserAccessMatchValue;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;

/**
 * Base for Roles commands, contains common functions for Roles operations
 */
public abstract class BaseRolesCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(BaseRolesCommand.class);

    private Map<String,String> resourceNameToResourceMap = null;
    private Map<String,String> resourceToResourceNameMap = null;

    private static Set<String[]> commandAliases = new HashSet<String[]>();
    static {
        commandAliases.add(new String[] { "admins" });
        try {
            Class.forName(X500PrincipalAccessMatchValue.class.getName());
            Class.forName(CliUserAccessMatchValue.class.getName());
        } catch (ClassNotFoundException e) {
            log.error("Failure during match value initialization", e);
        }
    }

    @Override
    public String[] getCommandPath() {
        return new String[] { "roles" };
    }

    @Override
    public Set<String[]> getCommandPathAliases() {
        return commandAliases;
    }

    @Override
    protected abstract Logger getLogger();

    /** @return a Map<resourceName,resource> for authorized resources (cached in this remote JVM) */
    public Map<String, String> getResourceNameToResourceMap() {
        if (resourceNameToResourceMap==null) {
            final Map<String,String> authorizedResourcesMap = EjbRemoteHelper.INSTANCE.getRemoteSession(AuthorizationSystemSessionRemote.class).
                    getAllResources(getAuthenticationToken(), false);
            resourceNameToResourceMap = new HashMap<>();
            for (final Entry<String,String> entry: authorizedResourcesMap.entrySet()) {
                resourceNameToResourceMap.put(entry.getValue(), entry.getKey());
            }
        }
        return resourceNameToResourceMap;
    }

    /** @return a Map<resource,resourceName> for authorized resources (cached in this remote JVM) */
    public Map<String, String> getResourceToResourceNameMap() {
        if (resourceToResourceNameMap==null) {
            resourceToResourceNameMap = EjbRemoteHelper.INSTANCE.getRemoteSession(AuthorizationSystemSessionRemote.class).
                    getAllResources(getAuthenticationToken(), false);
        }
        return resourceToResourceNameMap;
    }
}
