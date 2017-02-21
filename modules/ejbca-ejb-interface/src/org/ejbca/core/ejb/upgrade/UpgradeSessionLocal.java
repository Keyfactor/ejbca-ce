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
import java.util.concurrent.Future;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleNotFoundException;

/**
 * Local interface for UpgradeSession.
 */
@Local
public interface UpgradeSessionLocal  extends UpgradeSession{
    
    /** Performs operations before the upgrade, and can handle fresh installations specially */
    void performPreUpgrade(final boolean isFreshInstallation);

	/** Perform upgrades that can run side by side with older EJBCA versions. */
	boolean performUpgrade();

	/** Perform upgrades that require all nodes connected to the same database to run the current EJBCA version. */
    Future<Boolean> startPostUpgrade();

    /** @return true if post upgrade is required */
    boolean isPostUpgradeNeeded();

    /** @return EJBCA version of the database content that can be upgraded while running older EJBCAs on the same database. */
    String getLastUpgradedToVersion();

    /** @return EJBCA version of the database content that can be upgraded after all nodes run the same EJBCA version. */
    String getLastPostUpgradedToVersion();

    /** @return the epoch time of when the post-upgrade was last started in the cluster */
    long getPostUpgradeStarted();

    /** @return true if the endEntityProfileId column in CertificateData has been populated. */
    boolean isEndEntityProfileInCertificateData();

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
	AdminGroupData replaceAccessRulesInRoleNoAuth(final AuthenticationToken authenticationToken, final AdminGroupData role,
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
    void migrateDatabase651() throws UpgradeFailedException;
    /** For internal user from UpgradeSessionBean only! */
    void migrateDatabase660() throws UpgradeFailedException;
    /** For internal user from UpgradeSessionBean only! */
    void migrateDatabase680() throws UpgradeFailedException;

    /** Persist the time when the post-upgrade starts or 0L when it is no longer running. */
    boolean setPostUpgradeStarted(long startTimeMs);

    /**
     * Takes two versions and compares the first and the second versions to each other
     * 
     * @param first a version number
     * @param second a version number
     * @return true of the first version is lower (1.0 < 2.0) than the second, false otherwise. 
     */
    boolean isLesserThan(String first, String second);
}
