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
package org.ejbca.core.ejb.ca.store;

import javax.ejb.Remote;

/**
 * Remote interface for CertificateStoreSession.
 */
@Remote
public interface CertificateStoreSessionRemote {
    /**
     * Stores a certificate.
     * 
     * @param incert
     *            The certificate to be stored.
     * @param cafp
     *            Fingerprint (hex) of the CAs certificate.
     * @param username
     *            username of end entity owning the certificate.
     * @param status
     *            Status of the certificate (from CertificateData).
     * @param type
     *            Type of certificate (CERTTYPE_ENDENTITY etc from
     *            CertificateDataBean).
     * @param certificateProfileId
     *            the certificate profile id this cert was issued under
     * @param tag
     *            a custom string tagging this certificate for some purpose
     * @return true if storage was successful.
     * @throws CreateException
     *             if the certificate can not be stored in the database
     */
    public boolean storeCertificate(org.ejbca.core.model.log.Admin admin, java.security.cert.Certificate incert, java.lang.String username,
            java.lang.String cafp, int status, int type, int certificateProfileId, java.lang.String tag, long updateTime) throws javax.ejb.CreateException,
            java.rmi.RemoteException;

    /**
     * Lists fingerprint (primary key) of ALL certificates in the database.
     * NOTE: Caution should be taken with this method as execution may be very
     * heavy indeed if many certificates exist in the database (imagine what
     * happens if there are millinos of certificates in the DB!). Should only be
     * used for testing purposes.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param issuerdn
     *            the dn of the certificates issuer.
     * @return Collection of fingerprints, i.e. Strings, reverse ordered by
     *         expireDate where last expireDate is first in array.
     */
    public java.util.Collection listAllCertificates(org.ejbca.core.model.log.Admin admin, java.lang.String issuerdn) throws java.rmi.RemoteException;

    /**
     * Lists RevokedCertInfo of ALL revoked certificates (status =
     * CertificateDataBean.CERT_REVOKED) in the database from a certain issuer.
     * NOTE: Caution should be taken with this method as execution may be very
     * heavy indeed if many certificates exist in the database (imagine what
     * happens if there are millinos of certificates in the DB!). Should only be
     * used for testing purposes.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param issuerdn
     *            the dn of the certificates issuer.
     * @param lastbasecrldate
     *            a date (Date.getTime()) of last base CRL or -1 for a complete
     *            CRL
     * @return Collection of RevokedCertInfo, reverse ordered by expireDate
     *         where last expireDate is first in array.
     */
    public java.util.Collection listRevokedCertInfo(org.ejbca.core.model.log.Admin admin, java.lang.String issuerdn, long lastbasecrldate)
            throws java.rmi.RemoteException;

    /**
     * Lists certificates for a given subject signed by the given issuer.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param subjectDN
     *            the DN of the subject whos certificates will be retrieved.
     * @param issuerDN
     *            the dn of the certificates issuer.
     * @return Collection of Certificates (java.security.cert.Certificate) in no
     *         specified order or an empty Collection.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public java.util.Collection findCertificatesBySubjectAndIssuer(org.ejbca.core.model.log.Admin admin, java.lang.String subjectDN, java.lang.String issuerDN)
            throws java.rmi.RemoteException;

    public java.util.Set findUsernamesByIssuerDNAndSubjectDN(org.ejbca.core.model.log.Admin admin, java.lang.String issuerDN, java.lang.String subjectDN)
            throws java.rmi.RemoteException;

    public java.util.Set findUsernamesByIssuerDNAndSubjectKeyId(org.ejbca.core.model.log.Admin admin, java.lang.String issuerDN, byte[] subjectKeyId)
            throws java.rmi.RemoteException;

    /**
     * Lists certificates for a given subject.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param subjectDN
     *            the DN of the subject whos certificates will be retrieved.
     * @return Collection of Certificates (java.security.cert.Certificate) in no
     *         specified order or an empty Collection.
     */
    public java.util.Collection findCertificatesBySubject(org.ejbca.core.model.log.Admin admin, java.lang.String subjectDN) throws java.rmi.RemoteException;

    public java.util.Collection findCertificatesByExpireTime(org.ejbca.core.model.log.Admin admin, java.util.Date expireTime) throws java.rmi.RemoteException;

    /**
     * Finds usernames of users having certificate(s) expiring within a
     * specified time and that has status "active" or "notifiedaboutexpiration".
     * 
     * @see org.ejbca.core.model.SecConst#CERT_ACTIVE
     * @see org.ejbca.core.model.SecConst#CERT_NOTIFIEDABOUTEXPIRATION
     */
    public java.util.Collection findCertificatesByExpireTimeWithLimit(org.ejbca.core.model.log.Admin admin, java.util.Date expiretime)
            throws java.rmi.RemoteException;

    /**
     * Finds a certificate specified by issuer DN and serial number.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param issuerDN
     *            issuer DN of the desired certificate.
     * @param serno
     *            serial number of the desired certificate!
     * @return Certificate if found or null
     */
    public java.security.cert.Certificate findCertificateByIssuerAndSerno(org.ejbca.core.model.log.Admin admin, java.lang.String issuerDN,
            java.math.BigInteger serno) throws java.rmi.RemoteException;

    /**
     * Implements ICertificateStoreSession::findCertificatesByIssuerAndSernos.
     * <p/>
     * The method retrives all certificates from a specific issuer which are
     * identified by list of serial numbers. The collection will be empty if the
     * issuerDN is <tt>null</tt>/empty or the collection of serial numbers is
     * empty.
     * 
     * @param admin
     * @param issuerDN
     *            the subjectDN of a CA certificate
     * @param sernos
     *            a collection of certificate serialnumbers
     * @return Collection a list of certificates; never <tt>null</tt>
     */
    public java.util.Collection findCertificatesByIssuerAndSernos(org.ejbca.core.model.log.Admin admin, java.lang.String issuerDN, java.util.Collection sernos)
            throws java.rmi.RemoteException;

    /**
     * Finds certificate(s) for a given serialnumber.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param serno
     *            the serialnumber of the certificate(s) that will be retrieved
     * @return Certificate or null if none found.
     */
    public java.util.Collection findCertificatesBySerno(org.ejbca.core.model.log.Admin admin, java.math.BigInteger serno) throws java.rmi.RemoteException;

    /**
     * Finds username for a given certificate serial number.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param serno
     *            the serialnumber of the certificate to find username for.
     * @return username or null if none found.
     */
    public java.lang.String findUsernameByCertSerno(org.ejbca.core.model.log.Admin admin, java.math.BigInteger serno, java.lang.String issuerdn)
            throws java.rmi.RemoteException;

    /**
     * Finds certificate(s) for a given username.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param username
     *            the username of the certificate(s) that will be retrieved
     * @return Collection of Certificates ordered by expire date, with last
     *         expire date first, or null if none found.
     */
    public java.util.Collection findCertificatesByUsername(org.ejbca.core.model.log.Admin admin, java.lang.String username) throws java.rmi.RemoteException;

    /**
     * Finds certificate(s) for a given username and status.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param username
     *            the username of the certificate(s) that will be retrieved
     * @param status
     *            the status of the CertificateDataBean.CERT_ constants
     * @return Collection of Certificates ordered by expire date, with last
     *         expire date first, or empty list if user can not be found
     */
    public java.util.Collection findCertificatesByUsernameAndStatus(org.ejbca.core.model.log.Admin admin, java.lang.String username, int status)
            throws java.rmi.RemoteException;

    /**
     * Gets certificate info, which is basically all fields except the
     * certificate itself. Note: this methid should not be used within a
     * transaction where the reading of this info might depend on something
     * stored earlier in the transaction. This is because this method uses
     * direct SQL.
     * 
     * @return CertificateInfo or null if certificate does not exist.
     */
    public org.ejbca.core.model.ca.store.CertificateInfo getCertificateInfo(org.ejbca.core.model.log.Admin admin, java.lang.String fingerprint)
            throws java.rmi.RemoteException;

    public java.security.cert.Certificate findCertificateByFingerprint(org.ejbca.core.model.log.Admin admin, java.lang.String fingerprint)
            throws java.rmi.RemoteException;

    /**
     * Lists all active (status = 20) certificates of a specific type and if
     * given from a specific issuer.
     * <p/>
     * The type is the bitwise OR value of the types listed int
     * {@link org.ejbca.core.ejb.ca.store.CertificateDataBean}:<br>
     * <ul>
     * <li><tt>CERTTYPE_ENDENTITY</tt><br>
     * An user or machine certificate, which identifies a subject.</li>
     * <li><tt>CERTTYPE_CA</tt><br>
     * A CA certificate which is <b>not</b> a root CA.</li>
     * <li><tt>CERTTYPE_ROOTCA</tt><br>
     * A Root CA certificate.</li>
     * </ul>
     * <p/>
     * Usage examples:<br>
     * <ol>
     * <li>Get all root CA certificates
     * <p/>
     * <code> ... ICertificateStoreSessionRemote itf = ... Collection certs = itf.findCertificatesByType(adm, CertificateDataBean.CERTTYPE_ROOTCA, null); ... </code>
     * </li>
     * <li>Get all subordinate CA certificates for a specific Root CA. It is
     * assumed that the <tt>subjectDN</tt> of the Root CA certificate is located
     * in the variable <tt>issuer</tt>.
     * <p/>
     * <code> ... ICertificateStoreSessionRemote itf = ... Certficate rootCA = ... String issuer = rootCA.getSubjectDN(); Collection certs = itf.findCertificatesByType(adm, CertificateDataBean.CERTTYPE_SUBCA, issuer); ... </code>
     * </li>
     * <li>Get <b>all</b> CA certificates.
     * <p/>
     * <code> ... ICertificateStoreSessionRemote itf = ... Collection certs = itf.findCertificatesByType(adm, CertificateDataBean.CERTTYPE_SUBCA + CERTTYPE_ROOTCA, null); ... </code>
     * </li>
     * </ol>
     * 
     * @param admin
     * @param issuerDN
     *            get all certificates issued by a specific issuer. If
     *            <tt>null</tt> or empty return certificates regardless of the
     *            issuer.
     * @param type
     *            CERTTYPE_* types from CertificateDataBean
     * @return Collection Collection of Certificate, never <tt>null</tt>
     */
    public java.util.Collection findCertificatesByType(org.ejbca.core.model.log.Admin admin, int type, java.lang.String issuerDN)
            throws java.rmi.RemoteException;

    /**
     * Method that sets status CertificateDataBean.CERT_ARCHIVED on the
     * certificate data, only used for testing. Can only be performed by an
     * Admin.TYPE_INTERNALUSER. Normally ARCHIVED is set by the CRL creation
     * job, after a certificate has expired and been added to a CRL (expired
     * certificates that are revoked must be present on at least one CRL).
     */
    public void setArchivedStatus(org.ejbca.core.model.log.Admin admin, java.lang.String fingerprint)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, java.rmi.RemoteException;

    /**
     * Set the status of certificate with given serno to revoked.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param issuerdn
     *            Issuer of certificate to be removed.
     * @param serno
     *            the serno of certificate to revoke.
     * @param publishers
     *            and array of publiserids (Integer) of publishers to revoke the
     *            certificate in.
     * @param reason
     *            the reason of the revokation. (One of the
     *            RevokedCertInfo.REVOKATION_REASON constants.)
     * @param userDataDN
     *            if an DN object is not found in the certificate, the object
     *            could be taken from user data instead.
     */
    public void setRevokeStatus(org.ejbca.core.model.log.Admin admin, java.lang.String issuerdn, java.math.BigInteger serno, java.util.Collection publishers,
            int reason, java.lang.String userDataDN) throws java.rmi.RemoteException;

    /**
     * Revokes a certificate (already revoked by the CA), in the database
     * 
     * @param cert
     *            The DER coded Certificate that has been revoked.
     * @param publishers
     *            and array of publiserids (Integer) of publishers to revoke the
     *            certificate in.
     */
    public void revokeCertificate(org.ejbca.core.model.log.Admin admin, java.security.cert.Certificate cert, java.util.Collection publishers, int reason,
            java.lang.String userDataDN) throws java.rmi.RemoteException;

    /**
     * Method revoking all certificates generated by the specified issuerdn.
     * Sets revokedate to current time. Should only be called by CAAdminBean
     * when a CA is about to be revoked. TODO: Does not publish revocations to
     * publishers!!!
     * 
     * @param admin
     *            the administrator performing the event.
     * @param issuerdn
     *            the dn of CA about to be revoked
     * @param reason
     *            the reason of revokation.
     */
    public void revokeAllCertByCA(org.ejbca.core.model.log.Admin admin, java.lang.String issuerdn, int reason) throws java.rmi.RemoteException;

    /**
     * Method that checks if a users all certificates have been revoked.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param username
     *            the username to check for.
     * @return returns true if all certificates are revoked.
     */
    public boolean checkIfAllRevoked(org.ejbca.core.model.log.Admin admin, java.lang.String username) throws java.rmi.RemoteException;

    /**
     * Checks if a certificate is revoked.
     * 
     * @param issuerDN
     *            the DN of the issuer.
     * @param serno
     *            the serialnumber of the certificate that will be checked
     * @return true if the certificate is revoked or can not be found in the
     *         database, false if it exists and is not revoked.
     */
    public boolean isRevoked(java.lang.String issuerDN, java.math.BigInteger serno) throws java.rmi.RemoteException;

    /**
     * Get status fast.
     * 
     * @param issuerDN
     * @param serno
     * @return the status of the certificate
     */
    public org.ejbca.core.ejb.ca.store.CertificateStatus getStatus(java.lang.String issuerDN, java.math.BigInteger serno) throws java.rmi.RemoteException;

    /**
     * Method that authenticates a certificate by checking validity and lookup
     * if certificate is revoked.
     * 
     * @param certificate
     *            the certificate to be authenticated.
     * @param requireAdminCertificateInDatabase
     *            if true the certificate has to exist in the database
     * @throws AuthenticationFailedException
     *             if authentication failed.
     */
    public void authenticate(java.security.cert.X509Certificate certificate, boolean requireAdminCertificateInDatabase)
            throws org.ejbca.core.model.authorization.AuthenticationFailedException, java.rmi.RemoteException;

    /**
     * Checks the table protection information for a certificate data row
     * 
     * @param admin
     *            Administrator performing the operation
     * @param issuerDN
     *            the DN of the issuer.
     * @param serno
     *            the serialnumber of the certificate that will be checked
     */
    public void verifyProtection(org.ejbca.core.model.log.Admin admin, java.lang.String issuerDN, java.math.BigInteger serno) throws java.rmi.RemoteException;

    /**
     * Method used to add a CertReqHistory to database
     * 
     * @param admin
     *            calling the methods
     * @param cert
     *            the certificate to store (Only X509Certificate used for now)
     * @param useradmindata
     *            the user information used when issuing the certificate.
     */
    public void addCertReqHistoryData(org.ejbca.core.model.log.Admin admin, java.security.cert.Certificate cert,
            org.ejbca.core.model.ra.UserDataVO useradmindata) throws java.rmi.RemoteException;

    /**
     * Method to remove CertReqHistory data.
     * 
     * @param admin
     * @param certFingerprint
     *            the primary key.
     */
    public void removeCertReqHistoryData(org.ejbca.core.model.log.Admin admin, java.lang.String certFingerprint) throws java.rmi.RemoteException;

    /**
     * Retrieves the certificate request data belonging to given certificate
     * serialnumber and issuerdn
     * 
     * @param admin
     * @param certificateSN
     *            serial number of the certificate
     * @param issuerDN
     * @return the CertReqHistory or null if no data is stored with the
     *         certificate.
     */
    public org.ejbca.core.model.ca.store.CertReqHistory getCertReqHistory(org.ejbca.core.model.log.Admin admin, java.math.BigInteger certificateSN,
            java.lang.String issuerDN) throws java.rmi.RemoteException;

    /**
     * Retrieves all cert request datas belonging to a user.
     * 
     * @param admin
     * @param username
     * @return a collection of CertReqHistory
     */
    public java.util.List getCertReqHistory(org.ejbca.core.model.log.Admin admin, java.lang.String username) throws java.rmi.RemoteException;

    /**
     * A method designed to be called at startuptime to (possibly) upgrade
     * certificate profiles. This method will read all Certificate Profiles and
     * as a side-effect upgrade them if the version if changed for upgrade. Can
     * have a side-effect of upgrading a profile, therefore the Required
     * transaction setting.
     * 
     * @param admin
     *            administrator calling the method
     */
    public void initializeAndUpgradeProfiles(org.ejbca.core.model.log.Admin admin) throws java.rmi.RemoteException;

    /**
     * Adds a certificate profile to the database.
     * 
     * @param admin
     *            administrator performing the task
     * @param certificateprofilename
     *            readable name of new certificate profile
     * @param certificateprofile
     *            the profile to be added
     */
    public void addCertificateProfile(org.ejbca.core.model.log.Admin admin, java.lang.String certificateprofilename,
            org.ejbca.core.model.ca.certificateprofiles.CertificateProfile certificateprofile)
            throws org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException, java.rmi.RemoteException;

    /**
     * Adds a certificate profile to the database.
     * 
     * @param admin
     *            administrator performing the task
     * @param certificateprofileid
     *            internal ID of new certificate profile, use only if you know
     *            it's right.
     * @param certificateprofilename
     *            readable name of new certificate profile
     * @param certificateprofile
     *            the profile to be added
     */
    public void addCertificateProfile(org.ejbca.core.model.log.Admin admin, int certificateprofileid, java.lang.String certificateprofilename,
            org.ejbca.core.model.ca.certificateprofiles.CertificateProfile certificateprofile)
            throws org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException, java.rmi.RemoteException;

    /**
     * Adds a certificateprofile with the same content as the original
     * certificateprofile,
     * 
     * @param admin
     *            Administrator performing the operation
     * @param originalcertificateprofilename
     *            readable name of old certificate profile
     * @param newcertificateprofilename
     *            readable name of new certificate profile
     */
    public void cloneCertificateProfile(org.ejbca.core.model.log.Admin admin, java.lang.String originalcertificateprofilename,
            java.lang.String newcertificateprofilename, java.util.Collection authorizedCaIds)
            throws org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException, java.rmi.RemoteException;

    /**
     * Removes a certificateprofile from the database, does not throw any errors
     * if the profile does not exist, but it does log a message.
     * 
     * @param admin
     *            Administrator performing the operation
     */
    public void removeCertificateProfile(org.ejbca.core.model.log.Admin admin, java.lang.String certificateprofilename) throws java.rmi.RemoteException;

    /**
     * Renames a certificateprofile
     */
    public void renameCertificateProfile(org.ejbca.core.model.log.Admin admin, java.lang.String oldcertificateprofilename,
            java.lang.String newcertificateprofilename) throws org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException,
            java.rmi.RemoteException;

    /**
     * Updates certificateprofile data
     * 
     * @param admin
     *            Administrator performing the operation
     */
    public void changeCertificateProfile(org.ejbca.core.model.log.Admin admin, java.lang.String certificateprofilename,
            org.ejbca.core.model.ca.certificateprofiles.CertificateProfile certificateprofile) throws java.rmi.RemoteException;

    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     * 
     * @param certprofiletype
     *            should be either CertificateDataBean.CERTTYPE_ENDENTITY,
     *            CertificateDataBean.CERTTYPE_SUBCA,
     *            CertificateDataBean.CERTTYPE_ROOTCA,
     *            CertificateDataBean.CERTTYPE_HARDTOKEN (i.e EndEntity
     *            certificates and Hardtoken fixed profiles) or 0 for all.
     *            Retrives certificate profile names sorted.
     * @param authorizedCaIds
     *            Collection<Integer> of authorized CA Ids for the specified
     *            Admin
     * @return Collection of id:s (Integer)
     */
    public java.util.Collection getAuthorizedCertificateProfileIds(org.ejbca.core.model.log.Admin admin, int certprofiletype,
            java.util.Collection authorizedCaIds) throws java.rmi.RemoteException;

    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name
     * (String).
     * 
     * @param admin
     *            Administrator performing the operation
     */
    public java.util.HashMap getCertificateProfileIdToNameMap(org.ejbca.core.model.log.Admin admin) throws java.rmi.RemoteException;

    /**
     * Retrives a named certificate profile or null if none was found.
     */
    public org.ejbca.core.model.ca.certificateprofiles.CertificateProfile getCertificateProfile(org.ejbca.core.model.log.Admin admin,
            java.lang.String certificateprofilename) throws java.rmi.RemoteException;

    /**
     * Finds a certificate profile by id.
     * 
     * @param admin
     *            Administrator performing the operation
     */
    public org.ejbca.core.model.ca.certificateprofiles.CertificateProfile getCertificateProfile(org.ejbca.core.model.log.Admin admin, int id)
            throws java.rmi.RemoteException;

    /**
     * Returns a certificate profile id, given it's certificate profile name
     * 
     * @param admin
     *            Administrator performing the operation
     * @return the id or 0 if certificateprofile cannot be found.
     */
    public int getCertificateProfileId(org.ejbca.core.model.log.Admin admin, java.lang.String certificateprofilename) throws java.rmi.RemoteException;

    /**
     * Returns a certificateprofiles name given it's id.
     * 
     * @param admin
     *            Administrator performing the operation
     * @return certificateprofilename or null if certificateprofile id doesn't
     *         exists.
     */
    public java.lang.String getCertificateProfileName(org.ejbca.core.model.log.Admin admin, int id) throws java.rmi.RemoteException;

    /**
     * Method to check if a CA exists in any of the certificate profiles. Used
     * to avoid desyncronization of CA data.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param caid
     *            the caid to search for.
     * @return true if ca exists in any of the certificate profiles.
     */
    public boolean existsCAInCertificateProfiles(org.ejbca.core.model.log.Admin admin, int caid) throws java.rmi.RemoteException;

    /**
     * Method to check if a Publisher exists in any of the certificate profiles.
     * Used to avoid desyncronization of publisher data.
     * 
     * @param publisherid
     *            the publisherid to search for.
     * @return true if publisher exists in any of the certificate profiles.
     */
    public boolean existsPublisherInCertificateProfiles(org.ejbca.core.model.log.Admin admin, int publisherid) throws java.rmi.RemoteException;

    public int findFreeCertificateProfileId() throws java.rmi.RemoteException;
}
