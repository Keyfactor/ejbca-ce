/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificateprofile;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/** Session bean to manage certificate profiles, i.e. add, remove, find
 * 
 * In order to add or edit CertificateProfiles the admin needs access to:
 * - /ca_functionality/edit_certificate_profiles (StandardRules.CERTIFICATEPROFILEEDIT)
 * - the CAs set as "available CAs" with CA rules as /ca/<caid> (StandardRules.CAACCESS)
 * - if "available CAs" contains ANYCA (-1) the -1 caid privilege is needed.
 *
 * @version $Id$
 */
public interface CertificateProfileSession {

    /**
     * Adds a certificate profile to the database.
     * 
     * @param admin administrator performing the task
     * @param name readable name of new certificate profile
     * @param profile the profile to be added
     * @return the generated certificate profile id
     * 
     * @throws CertificateProfileExistsException if the profile already exists
	 * @throws AuthorizationDeniedException if admin is not authorized to edit certificate profile 
     */
    public int addCertificateProfile(AuthenticationToken admin, String name, CertificateProfile profile)
            throws CertificateProfileExistsException, AuthorizationDeniedException;

    /**
     * Adds a certificate profile to the database.
     * 
     * @param admin administrator performing the task
     * @param id internal ID of new certificate profile, use only if you know it's right.
     * @param name readable name of new certificate profile
     * @param profile the profile to be added
     * @return the generated certificate profile id
     * 
     * @throws CertificateProfileExistsException if the profile already exists
	 * @throws AuthorizationDeniedException if admin is not authorized to edit certificate profile 
     */
    public int addCertificateProfile(AuthenticationToken admin, int id, String name, CertificateProfile profile)
            throws CertificateProfileExistsException, AuthorizationDeniedException;

    /**
     * Updates certificate profile data
     * 
     * @param admin Administrator performing the operation
     * @param name readable name of new certificate profile
     * @param profile the profile to be added
     */
    void changeCertificateProfile(AuthenticationToken admin, String name, CertificateProfile profile) throws AuthorizationDeniedException;

    /**
	 * Do not use, use changeCertificateProfile instead. Used internally for
	 * testing only. Updates a profile without flushing caches.
	 */
	void internalChangeCertificateProfileNoFlushCache(AuthenticationToken admin, String name, CertificateProfile profile) throws AuthorizationDeniedException;

	/** Clear and reload certificate profile caches. */
	void flushProfileCache();

	/**
     * Adds a certificate profile with the same content as the original certificate profile.
     * 
     * @param admin Administrator performing the operation
     * @param orgname name of old certificate profile
     * @param newname name of new certificate profile
	 * @param availableCaIds list of CAid to replace the original list with, or null.
     */
    void cloneCertificateProfile(AuthenticationToken admin, String orgname, String newname,
            List<Integer> authorizedCaIds) throws CertificateProfileExistsException, CertificateProfileDoesNotExistException, AuthorizationDeniedException;

    /**
     * Retrieves a Collection of id:s (Integer) to authorized profiles. Only profiles that refer to CA's that the authentication token is 
     * authorized to will be returned. 
     * 
     * @param admin Administrator performing the operation
     * @param certprofiletype
     *            should be either CertificateConstants.CERTTYPE_ENDENTITY,
     *            CertificateConstants.CERTTYPE_SUBCA,
     *            CertificateConstants.CERTTYPE_ROOTCA,
     *            CertificateConstants.CERTTYPE_HARDTOKEN (i.e EndEntity
     *            certificates and Hardtoken fixed profiles) or 0 for all.
     *            Retrieves certificate profile names sorted.
     * @return Collection of id:s (Integer)
     */
    List<Integer> getAuthorizedCertificateProfileIds(AuthenticationToken admin, int certprofiletype);

    /**
     * Retrieves a Collection of id:s (Integer) of all certificate profiles which have non-existent CA Ids.
     * This requires access to the root resource (i.e. superadmin access). If access is denied then an empty
     * list is returned.
     */
    List<Integer> getAuthorizedCertificateProfileWithMissingCAs(AuthenticationToken admin);

    /**
     * Finds a certificate profile by id.
     * 
     * @param id certificate profile id
     * @return Certificate profile (cloned) or null if it can not be found.
     */
    CertificateProfile getCertificateProfile(int id);

    /**
     * Retrieves a named certificate profile or null if none was found.
     * 
     * @param name certificate profile name
     * @return Certificate profile (cloned) or null if it can not be found.
     */
    CertificateProfile getCertificateProfile(String name);

    /**
     * Returns a certificate profile id, given it's certificate profile name.
     * 
     * @param name certificate profile name
     * @return the id or 0 if certificate profile cannot be found.
     */
    int getCertificateProfileId(String name);

    /**
     * Returns a certificate profiles name given it's id.
     * 
     * @param id certificate profile id
     * @return certificate profile name or null if certificate profile id does not exist.
     */
    String getCertificateProfileName(int id);

    /**
     * Method creating a Map mapping profile id (Integer) to profile name
     * (String).
     */
    Map<Integer, String> getCertificateProfileIdToNameMap();

    /**
     * A method designed to be called at startuptime to (possibly) upgrade
     * certificate profiles. This method will read all Certificate Profiles and
     * as a side-effect upgrade them if the version changed.
     */
    public void initializeAndUpgradeProfiles();

    /**
	 * Renames a certificate profile
	 * @param oldname the name of the certificate profile to rename
	 * @param newname the new name of the certificate profile
	 */
	void renameCertificateProfile(AuthenticationToken admin, String oldname, String newname)
	        throws CertificateProfileExistsException, AuthorizationDeniedException;

	/**
     * Removes a certificate profile from the database, does not throw any errors if the profile does not exist.
     *
     * @param admin Administrator performing the operation
     * @param name the name of the certificate profile to remove
     */
    public void removeCertificateProfile(AuthenticationToken admin, String name) throws AuthorizationDeniedException;

    /**
     * Method to check if a CA id exists in any of the certificate profiles. Used
     * to avoid desyncronization of CA data.
     * 
     * @param admin Administrator performing the operation
     * @param caid the caid to search for.
     * @return true if ca exists in any of the certificate profiles.
     */
    public boolean existsCAIdInCertificateProfiles(int caid);
    
    /**
     * Method to check if a Publisher id exists in any of the certificate profiles.
     * Used to avoid desynchronization of publisher data.
     * 
     * @param admin Administrator performing the operation
     * @param publisherid the publisherid to search for.
     * @return true if publisher exists in any of the certificate profiles.
     */
    public boolean existsPublisherIdInCertificateProfiles(int publisherid);

}
