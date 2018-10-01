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

import java.util.concurrent.Future;

import javax.ejb.Local;

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
    /** For internal user from UpgradeSessionBean only! */
    void migrateDatabase6101() throws UpgradeFailedException;
    /** For internal user from UpgradeSessionBean only! */
    void migrateDatabase6110() throws UpgradeFailedException;
    /** For internal user from UpgradeSessionBean only! */
    void migrateDatabase6120() throws UpgradeFailedException;
    /** For internal user from UpgradeSessionBean only! */
    void migrateDatabase6140() throws UpgradeFailedException;
    /** For internal user from UpgradeSessionBean only! */
    void migrateDatabase6150() throws UpgradeFailedException;

    
    /** Persist the time when the post-upgrade starts or 0L when it is no longer running. */
    boolean setPostUpgradeStarted(long startTimeMs);

    /**
     * Takes two versions and compares the first and the second versions to each other
     * Compares the max amount of numbers on both. So 6.1.2.3,6.1.2 will try to compare 4 numbers, adding a 0, i.e. 6.1.2.3,6.1.2.0 
     * 
     * @param first a version number
     * @param second a version number
     * @return true of the first version is lower (1.0 < 2.0) than the second, false otherwise. 
     */
    boolean isLesserThan(String first, String second);




}
