package se.anatom.ejbca.ca.store;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.exception.CertificateProfileExistsException;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.log.Admin;


/**
 * The CertificateStoreSession is the primary storage for certificates and CRL. The CA always puts
 * certificates and CRLs in the CertificateStoreSession session bean defined in ca/ejb-jar.xml.
 * The CertificateStoreSession is also used to retrieve and find certificates, retrieve CRLs,
 * check for revocation etc. the CertificateStoreSession implements the interface
 * ICertificateStoreSession. Remote interface for EJB.
 *
 * @version $Id: ICertificateStoreSessionRemote.java,v 1.23 2003-10-06 11:47:12 anatom Exp $
 */
public interface ICertificateStoreSessionRemote extends javax.ejb.EJBObject, IPublisherSessionRemote {


   /**
    * Lists fingerprint (primary key) of ALL certificates in the database.
    * NOTE: Caution should be taken with this method as execution may be very
    * heavy indeed if many certificates exist in the database (imagine what happens if
    * there are millinos of certificates in the DB!).
    * Should only be used for testing purposes.
    *
    * @return Collection of fingerprints, i.e. Strings, reverse ordered by expireDate where last expireDate is first in array.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection listAllCertificates(Admin admin, String issuerdn) throws RemoteException;

   /**
    * Lists certificates for a given subject.
    *
    * @param subjectDN the DN of the subject whos certificates will be retrieved.
    * @param issuer the dn of the certificates issuer.
    * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection findCertificatesBySubjectAndIssuer(Admin admin, String subjectDN, String issuer) throws RemoteException;


	/**
	 * Implements ICertificateStoreSession::findCertificateByIssuerAndSerno.
	 *
	 * @param admin DOCUMENT ME!
	 * @param issuerDN DOCUMENT ME!
	 * @param serno DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */                           
	public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno) throws RemoteException;
	
    /**
     * Finds certificate(s) for a given serialnumber.
     *
     * @param serno the serialnumber of the certificate(s) that will be retrieved
     *
     * @return Certificate or null if none found.
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public Collection findCertificatesBySerno(Admin admin, BigInteger serno)
        throws RemoteException;

    /**
     * Finds certificate(s) for a given usernaem.
     *
     * @param username the usernaem of the certificate(s) that will be retrieved
     *
     * @return Certificate or null if none found.
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public Collection findCertificatesByUsername(Admin admin, String username)
        throws RemoteException;

    /**
     * Finds username for a given certificate serial number.
     *
     * @param serno the serialnumber of the certificate to find username for.
     *
     * @return username or null if none found.
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public String findUsernameByCertSerno(Admin admin, BigInteger serno, String issuerdn)
        throws RemoteException;

    /**
     * Finds certificate which expire within a specified time.
     *
     * @param expireTime all certificates that expires before this date will be listed
     *
     * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or
     *         an empty Collection.
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public Collection findCertificatesByExpireTime(Admin admin, Date expireTime)
        throws RemoteException;


    /**
     * Finds certificate with specified fingerprint.
     *
     * @return certificate
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public Certificate findCertificateByFingerprint(Admin admin, String fingerprint)
        throws RemoteException;

	/**
	 * The method retrives all certificates from a specific issuer
	 * which are identified by list of serial numbers. The collection
	 * will be empty if the issuerDN is <tt>null</tt>/empty
	 * or the collection of serial numbers is empty.
	 *
	 * @param admin
	 * @param issuer the subjectDN of a CA certificate
	 * @param sernos a collection of certificate serialnumbers
	 *
	 * @return Collection a list of certificates; never <tt>null</tt>
	 */
	public Collection findCertificatesByIssuerAndSernos(Admin admin, String issuerDN, Collection sernos)
		throws RemoteException;

	/**
	 * Lists all certificates of a specific type and if
	 * given from a specific issuer.
	 *
	 * The type is the bitwise OR value of the types listed
	 * int {@link se.anatom.ejbca.SecConst}:<br>
	 * <ul>
	 * <li><tt>CERTTYPE_ENDENTITY</tt><br>
	 * An user or machine certificate, which identifies a subject.
	 * </li>
	 * <li><tt>CERTTYPE_CA</tt><br>
	 * A CA certificate which is <b>not</b> a root CA.
	 * </li>
	 * <li><tt>CERTTYPE_ROOTCA</tt><br>
	 * A Root CA certificate.
	 * </li>
	 * </ul>
	 * <p>
	 * Usage examples:<br>
	 * <ol>
	 * <li>Get all root CA certificates
	 * <p>
	 * <code>
	 * ...
	 * ICertificateStoreSessionRemote itf = ...
	 * Collection certs = itf.findCertificatesByType(adm,
	 *                                               SecConst.CERTTYPE_ROOTCA,
	 *                                               null);
	 * ...
	 * </code>
	 * </li>
	 * <li>Get all subordinate CA certificates for a specific
	 * Root CA. It is assumed that the <tt>subjectDN</tt> of the
	 * Root CA certificate is located in the variable <tt>issuer</tt>.
	 * <p>
	 * <code>
	 * ...
	 * ICertificateStoreSessionRemote itf = ...
	 * Certficate rootCA = ...
	 * String issuer = rootCA.getSubjectDN();
	 * Collection certs = itf.findCertificatesByType(adm,
	 *                                               SecConst.CERTTYPE_CA,
	 *                                               issuer);
	 * ...
	 * </code>
	 * </li>
	 * <li>Get <b>all</b> CA certificates.
	 * <p>
	 * <code>
	 * ...
	 * ICertificateStoreSessionRemote itf = ...
	 * Collection certs = itf.findCertificatesByType(adm,
	 *                                               SecConst.CERTTYPE_CA
	 *                                               + CERTTYPE_CA,
	 *                                               null);
	 * ...
	 * </code>
	 * </li>
	 * </ol>
	 *
	 * @param admin
	 * @param type
	 * @param issuerDN get all certificates issued by a specific issuer.
	 *                 If <tt>null</tt> or empty return certificates regardless of
	 *                 the issuer.
	 *
         * @return Collection Collection of X509Certificate, never <tt>null</tt>
	 *
	 * @throws RemoteException
	 */
	 public Collection findCertificatesByType(Admin admin, int type, String issuerDN)
		throws RemoteException;

    /**
     * Set the status of certificates of given dn to revoked.
     *
     * @param username the username of user to revoke certificates.
     * @param reason the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON
     *        constants.)
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public void setRevokeStatus(Admin admin, String username, int reason)
        throws RemoteException;

    /**
     * Set the status of certificate with  given serno to revoked.
     *
     * @param serno the serno of certificate to revoke.
     * @param reason the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @throws EJBException if a communication or other error occurs.
     */   
    public void setRevokeStatus(Admin admin, String issuerdn, BigInteger serno, int reason) throws RemoteException; 
   
   
	/**
	 * Method revoking all certificates generated by the specified issuerdn. Sets revokedate to current time.
	 * Should only be called by CAAdminBean when a CA is about to be revoked.
	 *  
	 * @param admin the administrator performing the event.
	 * @param issuerdn the dn of CA about to be revoked
	 * @param reason the reason of revokation.
	 * 
	 */
	public void revokeAllCertByCA(Admin admin, String issuerdn, int reason) throws RemoteException;
		   
    /**
     * Method that checks if a users all certificates have been revoked.
     *
     * @param username the username to check for.
     *
     * @return returns true if all certificates are revoked.
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public boolean checkIfAllRevoked(Admin admin, String username)
        throws RemoteException;

    /**
     * Checks if a certificate is revoked.
     *
     * @param issuerDN the DN of the issuer.
     * @param serno the serialnumber of the certificate that will be checked
     *
    * @return RevokedCertInfo with revocation information, with reason RevokedCertInfo.NOT_REVOKED if NOT revoked. Returns null if certificate is not found.
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public RevokedCertInfo isRevoked(Admin admin, String issuerDN, BigInteger serno)
        throws RemoteException;

	/**
	 * The method returns the revocation status for a list or certificate identified
	 * by the serialnumber.
	 *
	 * @param admin
	 * @param issuer the subjectDN of a CA certificate
	 * @param sernos a collection of certificate serialnumbers
	 *
	 * @return Collection a collection of {@link RevokedCertInfo} objects which
	 *                    reflect the revocation status of the given certificates.
	 */
	public Collection isRevoked(Admin admin, String issuerDN, Collection sernos) throws RemoteException;

    /**
    * Lists all revoked certificates, ie status = CERT_REVOKED.
    *
    * @return Collection of Strings containing fingerprint (primary key) of the revoced certificates. Reverse ordered by expireDate where last expireDate is first in array.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection listRevokedCertificates(Admin admin, String issuerdn) throws RemoteException;

   /**
    * Retrieves the latest CRL issued by this CA.
    *
    * @return X509CRL or null of no CRLs have been issued.
    * @throws EJBException if a communication or other error occurs.
    */
    public byte[] getLastCRL(Admin admin, String issuerdn) throws RemoteException;
    

   /**
    * Retrieves the information about the lastest CRL issued by this CA.
    *
    * @return CRLInfo of last CRL by CA.
    * @throws EJBException if a communication or other error occurs.
    */
    public CRLInfo getLastCRLInfo(Admin admin, String issuerdn) throws RemoteException;

   /**
    * Retrieves the highest CRLNumber issued by the CA.
    *
    * @return int.
    * @throws EJBException if a communication or other error occurs.
    */
    public int getLastCRLNumber(Admin admin, String issuerdn) throws RemoteException;
  

    /**
     * Adds a certificate profile to the database.
     *
     * @param admin administrator performing the task
     * @param certificateprofileid internal ID of new certificate profile, use only if you know it's right.
     * @param certificateprofilename readable name of new certificate profile
     * @param certificateprofile the profile to be added
     *
     * @return true if added succesfully, false if it already exist
     * @throws RemoteException if a communication or other error occurs.
     */
    public void addCertificateProfile(Admin admin, String certificateprofilename,
        CertificateProfile certificateprofile) throws CertificateProfileExistsException, RemoteException;

    /**
     * Adds a certificate profile to the database.
     *
     * @param admin administrator performing the task
     * @param certificateprofileid internal ID of new certificate profile, use only if you know it's right.
     * @param certificateprofilename readable name of new certificate profile
     * @param certificateprofile the profile to be added
     *
     * @return true if added succesfully, false if it already exist
     * @throws RemoteException if a communication or other error occurs.
     */
    public void addCertificateProfile(Admin admin, int certificateprofileid, String certificateprofilename, CertificateProfile certificateprofile) throws CertificateProfileExistsException, RemoteException;  
	/**
	 * Adds a certificateprofile  with the same content as the original certificateprofile,
	 *
	 * @return false if the new certificateprofilename already exists.
	 *
	 * @throws RemoteException if a communication or other error occurs.
	 */
    public void cloneCertificateProfile(Admin admin, String originalcertificateprofilename, String newcertificateprofilename) throws CertificateProfileExistsException, RemoteException;

     /**
     * Removes a certificateprofile from the database.
     * @throws EJBException if a communication or other error occurs.
     */
    public void removeCertificateProfile(Admin admin, String certificateprofilename) throws RemoteException;

     /**
     * Renames a certificateprofile
     */
    public void renameCertificateProfile(Admin admin, String oldcertificateprofilename, String newcertificateprofilename) throws CertificateProfileExistsException, RemoteException;

    /**
     * Updates certificateprofile data
     *
     * @return false if certificateprofilename doesn't exists
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public void changeCertificateProfile(Admin admin, String certificateprofilename,
        CertificateProfile certificateprofile) throws RemoteException;
    
    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     *
     * @param certprofiletype should be either SecConst.CERTTYPE_ENDENTITY, SecConst.CERTTYPE_SUBCA, SecConst.CERTTYPE_ROOTCA or 0 for all. 
     */
    public Collection getAuthorizedCertificateProfileIds(Admin admin, int certprofiletype) throws RemoteException;
    
    
    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name (String).
     */    
    public HashMap getCertificateProfileIdToNameMap(Admin admin) throws RemoteException;


    /**
     * Retrives a named certificate profile.
     */
    public CertificateProfile getCertificateProfile(Admin admin, String certificateprofilename) throws RemoteException;

     /**
     * Finds a certificate profile by id.
     */
    public CertificateProfile getCertificateProfile(Admin admin, int id) throws RemoteException;


     /**
     * Returns a certificate profile id, given it's certificate profile name
     *
     * @return the id or 0 if certificateprofile cannot be found.
     */
    public int getCertificateProfileId(Admin admin, String certificateprofilename) throws RemoteException;

     /**
     * Returns a certificateprofiles name given it's id.
     *
     * @return certificateprofilename or null if certificateprofile id doesn't exists.
     */
    public String getCertificateProfileName(Admin admin, int id) throws RemoteException;
    
     /**
     * Method to check if a CA exists in any of the certificate profiles. Used to avoid desyncronization of CA data.
     *
     * @param caid the caid to search for.
     * @return true if ca exists in any of the certificate profiles.
     */
    public boolean existsCAInCertificateProfiles(Admin admin, int caid) throws RemoteException;    
 
}
