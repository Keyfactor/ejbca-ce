/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.core.ejb.ca.store;

import java.util.Collection;
import java.util.Map;

import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.log.Admin;

/** Session bean to manage certificate profiles, i.e. add, remove, find
 * 
 * @author mikek
 * @version $Id$
 */
public interface CertificateProfileSession {

    /**
     * Adds a certificate profile to the database.
     * 
     * @param admin administrator performing the task
     * @param certificateprofilename readable name of new certificate profile
     * @param certificateprofile the profile to be added
     */
    public void addCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile)
            throws CertificateProfileExistsException;

    /**
     * Adds a certificate profile to the database.
     * 
     * @param admin administrator performing the task
     * @param certificateprofileid internal ID of new certificate profile, use
     *            only if you know it's right.
     * @param certificateprofilename readable name of new certificate profile
     * @param certificateprofile the profile to be added
     */
    public void addCertificateProfile(Admin admin, int certificateprofileid, String certificateprofilename, CertificateProfile certificateprofile)
            throws CertificateProfileExistsException;

    /**
     * Updates CertificateProfile data
     * @param admin Administrator performing the operation
     */
    void changeCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile);

    /**
     * Adds a CertificateProfile with the same content as the original
     * CertificateProfile,
     * 
     * @param admin Administrator performing the operation
     * @param originalcertificateprofilename
     *            readable name of old certificate profile
     * @param newcertificateprofilename
     *            readable name of new certificate profile
     */
    void cloneCertificateProfile(Admin admin, String originalcertificateprofilename, String newcertificateprofilename,
            Collection<Integer> authorizedCaIds) throws CertificateProfileExistsException;

    /**
     * Retrieves a Collection of id:s (Integer) to authorized profiles.
     * Retrieves certificate profile names sorted.
     * 
     * @param certprofiletype
     *            should be either CertificateDataBean.CERTTYPE_ENDENTITY,
     *            CertificateDataBean.CERTTYPE_SUBCA,
     *            CertificateDataBean.CERTTYPE_ROOTCA,
     *            CertificateDataBean.CERTTYPE_HARDTOKEN (i.e EndEntity
     *            certificates and Hardtoken fixed profiles) or 0 for all.
     * @param authorizedCaIds
     *            Collection<Integer> of authorized CA Ids for the specified
     *            Admin
     * @return Collection of id:s (Integer)
     */
    public Collection<Integer> getAuthorizedCertificateProfileIds(Admin admin, int certprofiletype, Collection<Integer> authorizedCaIds);

    /** Clear and reload certificate profile caches. */
    void flushProfileCache();

    /**
     * Finds a certificate profile by id.
     * 
     * @param admin Administrator performing the operation
     * @return CertificateProfile (cloned) or null if it can not be found.
     */
    CertificateProfile getCertificateProfile(Admin admin, int id);

    /** Retrieves a named certificate profile or null if none was found. */
    CertificateProfile getCertificateProfile(Admin admin, String certificateprofilename);

    /**
     * Do NOT use, use changeCertificateProfile instead. Used internally for
     * testing only. Updates a profile without flushing caches.
     */
    void internalChangeCertificateProfileNoFlushCache(Admin admin, String certificateprofilename, CertificateProfile certificateprofile);

    int findFreeCertificateProfileId();

    /**
     * Returns a certificate profile id, given it's certificate profile name
     * 
     * @param admin Administrator performing the operation
     * @return the id or 0 if CertificateProfile cannot be found.
     */
    int getCertificateProfileId(Admin admin, String certificateprofilename);

    /**
     * @param admin Administrator performing the operation
     * @return a CertificateProfile's name given it's id.
     */
    String getCertificateProfileName(Admin admin, int id);

    /**
     * Method creating a Map mapping profile id (Integer) to profile name
     * (String).
     * 
     * @param admin Administrator performing the operation
     */
    Map<Integer, String> getCertificateProfileIdToNameMap(Admin admin);

    /**
     * A method designed to be called at startup time to (possibly) upgrade
     * certificate profiles.
     * 
     * @param admin administrator calling the method
     */ 
    public void initializeAndUpgradeProfiles(Admin admin);

    /**
     * Removes a CertificateProfile from the database, does not throw any errors
     * if the profile does not exist, but it does log a message.
     * 
     * @param admin Administrator performing the operation
     */
    public void removeCertificateProfile(Admin admin, String certificateprofilename);

    /** Renames a CertificateProfile. */
    void renameCertificateProfile(Admin admin, String oldcertificateprofilename, String newcertificateprofilename)
            throws CertificateProfileExistsException;

    /**
     * Method to check if a CA exists in any of the End Entity certificate profiles. Used
     * to avoid desynchronization of CA data.
     *
     * @param admin Administrator performing the operation
     * @param caid  the caid to search for.
     * @return true if CA exists in any of the End Entity certificate profiles.
     */
    public boolean existsCAInCertificateProfiles(Admin admin, int caid);
    
    /**
     * Method to check if a Publisher exists in any of the certificate profiles.
     * Used to avoid desynchronization of publisher data.
     * 
     * @param publisherid the publisherid to search for.
     * @return true if publisher exists in any of the certificate profiles.
     */
    public boolean existsPublisherInCertificateProfiles(Admin admin, int publisherid);

}
