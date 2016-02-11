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
package org.ejbca.core.ejb.upgrade;

import java.util.Collection;
import java.util.List;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleNotFoundException;

/**
 * Local interface for UpgradeSession.
 */
@Local
public interface UpgradeSessionLocal  extends UpgradeSession{

	/** Perform upgrades that can run side by side with older EJBCA versions. */
	boolean performUpgrade();

	/** Perform upgrades that require all nodes connected to the same database to run the current EJBCA version. */
    boolean performPostUpgrade();

    /** @return true if post upgrade is required */
    boolean isPostUpgradeNeeded();

    /** @return EJBCA version of the database content that can be upgraded while running older EJBCAs on the same database. */
    String getLastUpgradedToVersion();

    /** @return EJBCA version of the database content that can be upgraded after all nodes run the same EJBCA version. */
    String getLastPostUpgradedToVersion();

    /** @return true if the AdminGroupData.cAId column still exists which indicates that this is EJBCA 4.0 or earlier. */
    boolean checkColumnExists500();

    /**
     * Required because the real method in RoleManagementSessionBean requires authorization to manipulate rules.
     * A bit of a catch-22. 
     * 
     * Never use this method except during upgrade.
     * 
     * @deprecated Remove this method once 4.0.x -> 5.0.x support has been dropped. 
     */
	RoleData replaceAccessRulesInRoleNoAuth(final AuthenticationToken authenticationToken, final RoleData role,
            final Collection<AccessRuleData> accessRules) throws RoleNotFoundException;

    /** For internal user from UpgradeSessionBean only! */
    void postMigrateDatabase400SmallTables();
    /** For internal user from UpgradeSessionBean only! */
    void postMigrateDatabase400HardTokenData(List<String> subSet);
    /** For internal user from UpgradeSessionBean only! */
	boolean migrateDatabase500(String dbtype);
    /** For internal user from UpgradeSessionBean only! */
    void migrateDatabase624() throws UpgradeFailedException;
    /** For internal user from UpgradeSessionBean only! */
    void migrateDatabase640() throws UpgradeFailedException;	
    /** For internal user from UpgradeSessionBean only! */
    void migrateDatabase642() throws UpgradeFailedException;
    /** For internal user from UpgradeSessionBean only! */
    void migrateDatabase650() throws UpgradeFailedException;    
}
