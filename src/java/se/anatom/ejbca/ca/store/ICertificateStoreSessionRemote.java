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
 * @version $Id: ICertificateStoreSessionRemote.java,v 1.27 2004-03-07 12:09:50 herrvendil Exp $
 */
public interface ICertificateStoreSessionRemote extends javax.ejb.EJBObject {


    /**
     * Stores a certificate.
     *
     * @param incert The certificate to be stored.
     * @param chainfp Fingerprint (hex) of the CAs certificate.
     * @param username username of end entity owning the certificate.
     * @param status Status of the certificate (from CertificateData).
     * @param type Type of certificate (from SecConst).
     *
     * @return true if storage was successful.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean storeCertificate(Admin admin, Certificate incert, String username, String cafp,
        int status, int type) throws RemoteException;

    /**
     * Stores a CRL
     *
     * @param incrl The DER coded CRL to be stored.
     * @param chainfp Fingerprint (hex) of the CAs certificate.
     * @param number CRL number.
     *
     * @return true if storage was successful.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number)
        throws RemoteException;

    /**
     * Revokes a certificate (already revoked by the CA), in the database
     *
     * @param cert The DER coded Certificate that has been revoked.
     * @param publishers and array of publiserids (Integer) of publishers to revoke the certificate in.  
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void revokeCertificate(Admin admin, Certificate cert, Collection publishers, int reason)
        throws RemoteException;    
    
	
   /**
    * Lists fingerprint (primary key) of ALL certificates in the database.
    * NOTE: Caution should be taken with this method as execution may be very
    * heavy indeed if many certificates exist in the database (imagine what happens if
    * there are millinos of certificates in the DB!).
    * Should only be used for testing purposes.
    *
    * @param admin Administrator performing the operation
    * @param issuerDN the dn of the certificates issuer.
    * @return Collection of fingerprints, i.e. Strings, reverse ordered by expireDate where last expireDate is first in array.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection listAllCertificates(Admin admin, String issuerdn) throws RemoteException;

   /**
    * Lists certificates for a given subject signed by the given issuer.
    *
    * @param admin Administrator performing the operation
    * @param subjectDN the DN of the subject whos certificates will be retrieved.
    * @param issuerDN the dn of the certificates issuer.
    * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection findCertificatesBySubjectAndIssuer(Admin admin, String subjectDN, String issuerDN) throws RemoteException;

    /**
     * Lists certificates for a given subject.
     *
     * @param admin Administrator performing the operation
     * @param subjectDN the DN of the subject whos certificates will be retrieved.
     * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
     * @throws EJBException if a communication or other error occurs.
     */
    public Collection findCertificatesBySubject(Admin admin, String subjectDN) throws RemoteException;

	/**
     * Finds a certificate specified by issuer DN and serial number.
	 *
     * @param admin Administrator performing the operation
	 * @param issuerDN issuer DN of the desired certificate.
	 * @param serno serial number of the desired certificate!
	 *
	 * @return Certificate if found or null
	 */                           
	public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno) throws RemoteException;
	
    /**
     * Finds certificate(s) for a given serialnumber.
     *
     * @param admin Administrator performing the operation
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
     * @param admin Administrator performing the operation
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
     * @param admin Administrator performing the operation
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
     * @param admin Administrator performing the operation
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
     * @param admin Administrator performing the operation
     * @return certificate or null if certificate doesn't exists
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
     * @param admin Administrator performing the operation
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
	 *                                               SecConst.CERTTYPE_SUBCA,
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
	 *                                               SecConst.CERTTYPE_SUBCA
	 *                                               + CERTTYPE_ROOTCA,
	 *                                               null);
	 * ...
	 * </code>
	 * </li>
	 * </ol>
	 *
     * @param admin Administrator performing the operation
	 * @param type CERTTYPE_* types from SecConst 
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
     * @param admin Administrator performing the operation
     * @param username the username of user to revoke certificates.
     * @param publishers and array of publiserids (Integer) of publishers to revoke the certificate in.  
     * @param reason the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON
     *        constants.)
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public void setRevokeStatus(Admin admin, String username, Collection publishers, int reason)
        throws RemoteException;

    /**
     * Set the status of certificate with  given serno to revoked.
     *
     * @param admin Administrator performing the operation
     * @param serno the serno of certificate to revoke.
     * @param publishers and array of publiserids (Integer) of publishers to revoke the certificate in.  
     * @param reason the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @throws EJBException if a communication or other error occurs.
     */   
    public void setRevokeStatus(Admin admin, String issuerdn, BigInteger serno, Collection publishers, int reason) throws RemoteException; 
   
   
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
     * @param admin Administrator performing the operation
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
     * @param admin Administrator performing the operation
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
     * @param admin Administrator performing the operation
	 * @param issuerDN the subjectDN of a CA certificate
	 * @param sernos a collection of certificate serialnumbers
	 *
	 * @return Collection a collection of {@link RevokedCertInfo} objects which
	 *                    reflect the revocation status of the given certificates.
	 */
	public Collection isRevoked(Admin admin, String issuerDN, Collection sernos) throws RemoteException;

    /**
    * Lists all revoked certificates, ie status = CERT_REVOKED.
    *
    * @param admin Administrator performing the operation
    * @return Collection of Strings containing fingerprint (primary key) of the revoced certificates. Reverse ordered by expireDate where last expireDate is first in array.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection listRevokedCertificates(Admin admin, String issuerdn) throws RemoteException;

   /**
    * Retrieves the latest CRL issued by this CA.
    *
    * @param admin Administrator performing the operation
    * @return X509CRL or null of no CRLs have been issued.
    * @throws EJBException if a communication or other error occurs.
    */
    public byte[] getLastCRL(Admin admin, String issuerdn) throws RemoteException;
    

   /**
    * Retrieves the information about the lastest CRL issued by this CA.
    *
    * @param admin Administrator performing the operation
    * @return CRLInfo of last CRL by CA.
    * @throws EJBException if a communication or other error occurs.
    */
    public CRLInfo getLastCRLInfo(Admin admin, String issuerdn) throws RemoteException;

   /**
    * Retrieves the highest CRLNumber issued by the CA.
    *
    * @param admin Administrator performing the operation
    * @param issuerdn the subjectDN of a CA certificate
    * @return int.
    * @throws EJBException if a communication or other error occurs.
    */
    public int getLastCRLNumber(Admin admin, String issuerdn) throws RemoteException;
  

    /**
     * Adds a certificate profile to the database.
     *
     * @param admin administrator performing the task
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
     * @param admin Administrator performing the operation
     * @param originalcertificateprofilename readable name of old certificate profile
     * @param newcertificateprofilename readable name of new certificate profile
	 * @return false if the new certificateprofilename already exists.
	 *
	 * @throws RemoteException if a communication or other error occurs.
	 */
    public void cloneCertificateProfile(Admin admin, String originalcertificateprofilename, String newcertificateprofilename) throws CertificateProfileExistsException, RemoteException;

     /**
     * Removes a certificateprofile from the database.
     *
     * @param admin Administrator performing the operation
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
     * @param admin Administrator performing the operation
     * @return false if certificateprofilename doesn't exists
     *
     * @throws RemoteException if a communication or other error occurs.
     */
    public void changeCertificateProfile(Admin admin, String certificateprofilename,
        CertificateProfile certificateprofile) throws RemoteException;
    
    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     *
     * @param admin Administrator performing the operation
     * @param certprofiletype should be either SecConst.CERTTYPE_ENDENTITY, SecConst.CERTTYPE_SUBCA, SecConst.CERTTYPE_ROOTCA or 0 for all. 
     */
    public Collection getAuthorizedCertificateProfileIds(Admin admin, int certprofiletype) throws RemoteException;
    
    
    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name (String).
     *
     * @param admin Administrator performing the operation
     */    
    public HashMap getCertificateProfileIdToNameMap(Admin admin) throws RemoteException;


    /**
     * Retrives a named certificate profile.
     */
    public CertificateProfile getCertificateProfile(Admin admin, String certificateprofilename) throws RemoteException;

     /**
     * Finds a certificate profile by id.
     
     * @param admin Administrator performing the operation
     */
    public CertificateProfile getCertificateProfile(Admin admin, int id) throws RemoteException;


     /**
     * Returns a certificate profile id, given it's certificate profile name
     *
     * @param admin Administrator performing the operation
     * @return the id or 0 if certificateprofile cannot be found.
     */
    public int getCertificateProfileId(Admin admin, String certificateprofilename) throws RemoteException;

     /**
     * Returns a certificateprofiles name given it's id.
     *
     * @param admin Administrator performing the operation
     * @return certificateprofilename or null if certificateprofile id doesn't exists.
     */
    public String getCertificateProfileName(Admin admin, int id) throws RemoteException;
    
     /**
     * Method to check if a CA exists in any of the certificate profiles. Used to avoid desyncronization of CA data.
     *
     * @param admin Administrator performing the operation
     * @param caid the caid to search for.
     * @return true if ca exists in any of the certificate profiles.
     */
    public boolean existsCAInCertificateProfiles(Admin admin, int caid) throws RemoteException;    
 
    /**
     * Method to check if a Publisher exists in any of the certificate profiles. Used to avoid desyncronization of publisher data.
     *
     * @param publisherid the publisherid to search for.
     * @return true if publisher exists in any of the certificate profiles.
     */
    public boolean existsPublisherInCertificateProfiles(Admin admin, int publisherid)throws RemoteException;    
    
}
