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

import java.util.List;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Session bean to manage certificate profiles, i.e. add, remove, find
 * <br/>
 * In order to add or edit CertificateProfiles the admin needs access to:
 * - /ca_functionality/edit_certificate_profiles (StandardRules.CERTIFICATEPROFILEEDIT)
 * - the CAs set as "available CAs" with CA rules as /ca/[caid] (StandardRules.CAACCESS)
 * - if "available CAs" contains ANYCA (-1) the -1 caid privilege is needed.
 * @version $Id$
 */
public interface CertificateProfileSession {

    /**
     * Adds a certificate profile to the database.
     * @param authenticationToken administrator performing the task
     * @param certificateProfileName readable name of new certificate profile
     * @param profile the profile to be added
     * @return the generated certificate profile id
     * @throws CertificateProfileExistsException if the profile already exists
	 * @throws AuthorizationDeniedException if admin is not authorized to edit certificate profile 
     */
    int addCertificateProfile(
            final AuthenticationToken authenticationToken,
            final String certificateProfileName,
            final CertificateProfile profile
    ) throws CertificateProfileExistsException, AuthorizationDeniedException;

    /**
     * Adds a certificate profile to the database.
     * @param authenticationToken administrator performing the task
     * @param certificateProfileId internal ID of new certificate profile, use only if you know it's right.
     * @param certificateProfileName readable name of new certificate profile
     * @param certificateProfile the profile to be added
     * @return the generated certificate profile id
     * @throws CertificateProfileExistsException if the profile already exists
	 * @throws AuthorizationDeniedException if admin is not authorized to edit certificate profile 
     */
    int addCertificateProfile(
            final AuthenticationToken authenticationToken,
            final int certificateProfileId,
            final String certificateProfileName,
            final CertificateProfile certificateProfile
    ) throws CertificateProfileExistsException, AuthorizationDeniedException;

    /**
     * Updates certificate profile data
     * @param authenticationToken Administrator performing the operation
     * @param certificateProfileName readable name of new certificate profile
     * @param certificateProfile the profile to be added
     * @throws AuthorizationDeniedException if admin is not authorized to change certificate profile
     */
    void changeCertificateProfile(
            final AuthenticationToken authenticationToken,
            final String certificateProfileName,
            final CertificateProfile certificateProfile
    ) throws AuthorizationDeniedException;

    /**
	 * Do not use, use changeCertificateProfile instead. Used internally for
	 * testing only. Updates a profile without flushing caches.
     * @param authenticationToken Administrator performing the operation
     * @param certificateProfileName readable name of certificate profile
     * @param certificateProfile the profile
     * @throws AuthorizationDeniedException if admin is not authorized
	 */
	void internalChangeCertificateProfileNoFlushCache(
	        final AuthenticationToken authenticationToken,
            final String certificateProfileName,
            final CertificateProfile certificateProfile
    ) throws AuthorizationDeniedException;

	/**
     * Clear and reload certificate profile caches.
     */
	void flushProfileCache();

	/**
     * Adds a certificate profile with the same content as the original certificate profile.
     * @param authenticationToken Administrator performing the operation
     * @param oldCertificateProfileName name of old certificate profile
     * @param newCertificateProfileName name of new certificate profile
	 * @param authorizedCaIds list of CAid to replace the original list with, or null.
     * @throws CertificateProfileExistsException if the profile already exists
     * @throws CertificateProfileDoesNotExistException if the profile does not exist
     * @throws AuthorizationDeniedException if admin is not authorized
     */
    void cloneCertificateProfile(
            final AuthenticationToken authenticationToken,
            final String oldCertificateProfileName,
            final String newCertificateProfileName,
            final List<Integer> authorizedCaIds
    ) throws CertificateProfileExistsException, CertificateProfileDoesNotExistException, AuthorizationDeniedException;

    /**
     * Retrieves a Collection of id:s (Integer) to authorized profiles. Only profiles that refer to CA's that
     * the authentication token is authorized to will be returned.
     * @param authenticationToken Administrator performing the operation
     * @param certificateProfileType
     *            should be either CertificateConstants.CERTTYPE_ENDENTITY,
     *            CertificateConstants.CERTTYPE_SUBCA,
     *            CertificateConstants.CERTTYPE_ROOTCA,
     *            or CertificateConstants.CERTTYPE_UNKNOWN for all.
     *            Retrieves certificate profile names sorted.
     * @return List of id's (Integer)
     */
    List<Integer> getAuthorizedCertificateProfileIds(
            final AuthenticationToken authenticationToken,
            final int certificateProfileType
    );

    /**
     * Retrieves a Collection of id:s (Integer) of all certificate profiles which have non-existent CA Ids.
     * This requires access to the root resource (i.e. superadmin access). If access is denied then an empty
     * list is returned.
     * @param authenticationToken Administrator performing the operation
     */
    List<Integer> getAuthorizedCertificateProfileWithMissingCAs(final AuthenticationToken authenticationToken);

    /**
     * Finds a certificate profile by id.
     * @param certificateProfileId certificate profile id
     * @return Certificate profile (cloned) or null if it can not be found.
     */
    CertificateProfile getCertificateProfile(final int certificateProfileId);

    /**
     * Retrieves a named certificate profile or null if none was found.
     * @param certificateProfileName certificate profile name
     * @return Certificate profile (cloned) or null if it can not be found.
     */
    CertificateProfile getCertificateProfile(final String certificateProfileName);

    /**
     * Returns a certificate profile id, given it's certificate profile name.
     * @param certificateProfileName certificate profile name
     * @return the id or 0 if certificate profile cannot be found.
     */
    int getCertificateProfileId(final String certificateProfileName);

    /**
     * Returns a certificate profiles name given it's id.
     * @param certificateProfileId certificate profile id
     * @return certificate profile name or null if certificate profile id does not exist.
     */
    String getCertificateProfileName(final int certificateProfileId);

    /**
     * Method creating a Map mapping profile id (Integer) to profile name (String).
     * @return Map of ids and names.
     */
    Map<Integer, String> getCertificateProfileIdToNameMap();

    /**
     * A method designed to be called at startup time to (possibly) upgrade certificate profiles. This method will
     * read all Certificate Profiles and as a side-effect upgrade them if the version changed.
     */
    void initializeAndUpgradeProfiles();

    /**
	 * Renames a certificate profile
	 * @param oldCertificateProfileName the name of the certificate profile to rename
	 * @param newCertificateProfileName the new name of the certificate profile
     * @throws CertificateProfileExistsException if the profile already exists
     * @throws AuthorizationDeniedException if admin is not authorized
	 */
	void renameCertificateProfile(
	        final AuthenticationToken authenticationToken,
            final String oldCertificateProfileName,
            final String newCertificateProfileName
    ) throws CertificateProfileExistsException, AuthorizationDeniedException;

	/**
     * Removes a certificate profile from the database, does not throw any errors if the profile does not exist.
     * @param authenticationToken Administrator performing the operation
     * @param certificateProfileName the name of the certificate profile to remove
     * @throws AuthorizationDeniedException if admin is not authorized
     */
    void removeCertificateProfile(
            final AuthenticationToken authenticationToken,
            final String certificateProfileName
    ) throws AuthorizationDeniedException;

    /**
     * Method to check if a CA id exists in any of the certificate profiles. Used to avoid desynchronization of CA data.
     * @param caId the caId to search for.
     * @return true if ca exists in any of the certificate profiles.
     */
    boolean existsCAIdInCertificateProfiles(int caId);
    
    /**
     * Method to check if a Publisher id exists in any of the certificate profiles.
     * Used to avoid desynchronization of publisher data.
     * @param publisherId the publisherid to search for.
     * @return true if publisher exists in any of the certificate profiles.
     */
    boolean existsPublisherIdInCertificateProfiles(int publisherId);

    /**
     * Returns the given certificate profile in XML format
     * @param authenticationToken the administrator requesting the action
     * @param profileId the id of the certificate profile
     * @throws CertificateProfileDoesNotExistException if the profile with the given ID didn't exist. 
     * @throws AuthorizationDeniedException if the profile contained CAs that the admin wasn't authorized to, or
     * the admin wasn't authorized to view profiles
     */
    byte[] getProfileAsXml(
            final AuthenticationToken authenticationToken,
            final int profileId
    ) throws CertificateProfileDoesNotExistException, AuthorizationDeniedException;

}
