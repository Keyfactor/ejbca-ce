
package se.anatom.ejbca.ca.store;

import java.util.Collection;
import java.util.Date;
import java.util.TreeMap;
import java.rmi.RemoteException;
import java.math.BigInteger;
import java.security.cert.Certificate;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.store.certificateprofiles.*;
import se.anatom.ejbca.log.Admin;

/** The CertificateStoreSession is the primary storage
 * for certificates and CRL. The CA always puts certificates and CRLs in the
 * CertificateStoreSession session bean defined in ca/ejb-jar.xml. The
 * CertificateStoreSession is also used to retrieve and find certificates,
 * retrieve CRLs, check for revocation etc. the CertificateStoreSession implements
 * the interface ICertificateStoreSession.
 *
 * Remote interface for EJB.
 *
 * @version $Id: ICertificateStoreSessionRemote.java,v 1.11 2003-01-12 17:16:29 anatom Exp $
 */
public interface ICertificateStoreSessionRemote extends javax.ejb.EJBObject, IPublisherSessionRemote  {

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
    public Collection listAllCertificates(Admin admin) throws RemoteException;

   /**
    * Lists certificates for a given subject.
    *
    * @param subjectDN the DN of the subject whos certificates will be retrieved.
    * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection findCertificatesBySubject(Admin admin, String subjectDN) throws RemoteException;

   /**
    * Finds certificate for a given issuer and serialnumber.
    *
    * @param issuerDN the DN of the issuer.
    * @param serno the serialnumber of the certificate that will be retrieved
    * @return Certificate or null if none found.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno) throws RemoteException;

    /**
    * Finds certificate(s) for a given serialnumber.
    * @param serno the serialnumber of the certificate(s) that will be retrieved
    * @return Certificate or null if none found.
    *
    * @throws EJBException if a communication or other error occurs.
    *
    */
    public Collection findCertificatesBySerno(Admin admin, BigInteger serno) throws RemoteException;
    
    /**
    * Finds certificate(s) for a given usernaem.
    * @param username the usernaem of the certificate(s) that will be retrieved
    * @return Certificate or null if none found.
    *
    * @throws EJBException if a communication or other error occurs.
    *
    */
    public Collection findCertificatesByUsername(Admin admin, String username) throws RemoteException;  


    /**
    * Finds username for a given certificate serial number.
    * @param serno the serialnumber of the certificate to find username for.
    * @return username or null if none found.
    *
    * @throws EJBException if a communication or other error occurs.
    *
    */    
    public String findUsernameByCertSerno(Admin admin, BigInteger serno) throws RemoteException;      


   /**
    * Finds certificate which expire within a specified time.
    *
    * @param expireTime all certificates that expires before this date will be listed
    * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection findCertificatesByExpireTime(Admin admin, Date expireTime) throws RemoteException;
    
     /** 
     * Set the status of certificates of given dn to revoked.
     * @param dn the dn of user to revoke certificates.
     * @param reason the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @throws EJBException if a communication or other error occurs.
     */
    public void setRevokeStatus(Admin admin, String dn, int reason) throws RemoteException;

     /**
     * Set the status of certificate with  given serno to revoked.
     * @param serno the serno of certificate to revoke.
     * @param reason the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @throws EJBException if a communication or other error occurs.
     */   
    public void setRevokeStatus(Admin admin, BigInteger serno, int reason) throws RemoteException; 
   
    /**
     *  Method that checks if a users all certificates have been revoked.
     *
     *  @param username the username to check for.
     *  @return returns true if all certificates are revoked.
     */
    public boolean checkIfAllRevoked(Admin admin, String username) throws RemoteException;

   /**
    * Checks if a certificate is revoked.
    *
    * @param issuerDN the DN of the issuer.
    * @param serno the serialnumber of the certificate that will be checked
    * @return null if certificate is NOT revoked, RevokedCertInfo if it IS revoked.
    * @throws EJBException if a communication or other error occurs.
    */
    public RevokedCertInfo isRevoked(Admin admin, String issuerDN, BigInteger serno) throws RemoteException;

    /**
    * Lists all revoked certificates, ie status = CERT_REVOKED.
    *
    * @return Collection of Strings containing fingerprint (primary key) of the revoced certificates. Reverse ordered by expireDate where last expireDate is first in array.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection listRevokedCertificates(Admin admin) throws RemoteException;

   /**
    * Retrieves the latest CRL issued by this CA.
    *
    * @return X509CRL or null of no CRLs have been issued.
    * @throws EJBException if a communication or other error occurs.
    */
    public byte[] getLastCRL(Admin admin) throws RemoteException;

   /**
    * Retrieves the highest CRLNumber issued by the CA.
    *
    * @return int.
    * @throws EJBException if a communication or other error occurs.
    */
    public int getLastCRLNumber(Admin admin) throws RemoteException;

    // Functions used for Certificate Types.

    /**
     * Adds a certificateprofile to the database.
     *
     * @return false if certificateprofilename already exists.
     * @throws EJBException if a communication or other error occurs.
     */        
    
    public boolean addCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile) throws RemoteException;   
    
     /**
     * Adds a certificateprofile  with the same content as the original certificateprofile,
     *
     * @return false if the new certificateprofilename already exists.
     * @throws EJBException if a communication or other error occurs.     
     */ 
    public boolean cloneCertificateProfile(Admin admin, String originalcertificateprofilename, String newcertificateprofilename) throws RemoteException;
    
     /**
     * Removes a certificateprofile from the database. 
     * 
     * @throws EJBException if a communication or other error occurs.   
     */ 
    public void removeCertificateProfile(Admin admin, String certificateprofilename) throws RemoteException;
    
     /**
     * Renames a certificateprofile.
     *
     * @return false if new name already exists
     * @throws EJBException if a communication or other error occurs.           
     */ 
    public boolean renameCertificateProfile(Admin admin, String oldcertificateprofilename, String newcertificateprofilename) throws RemoteException;   

    /**
     * Updates certificateprofile data
     *
     * @return false if certificateprofilename doesn't exists
     * @throws EJBException if a communication or other error occurs.
     */     
    
    public boolean changeCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile) throws RemoteException; 
    
      /**
       * Returns the available certificateprofile names.
       *
       * @return a collection of certificateprofilenames.
       * @throws EJBException if a communication or other error occurs.
       */       
    public Collection getCertificateProfileNames(Admin admin) throws RemoteException;

      /**
       * Returns the available certificateprofile.
       *
       * @return A collection of Profiles.
       * @throws EJBException if a communication or other error occurs.
       */        
    public TreeMap getCertificateProfiles(Admin admin) throws RemoteException;
    
      /**
       * Returns the specified certificateprofile.
       *
       * @return the certificateprofile data or null if profile doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public CertificateProfile getCertificateProfile(Admin admin, String certificateprofilename) throws RemoteException;
    
       /**
       * Returns the specified certificateprofile.
       *
       * @return the certificateprofile data or null if profile doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public CertificateProfile getCertificateProfile(Admin admin, int id) throws RemoteException;

      /**
       * Returns the number of available certificateprofiles.
       *
       * @return the number of available certificateprofiles.
       * @throws EJBException if a communication or other error occurs.
       */             
    public int getNumberOfCertificateProfiles(Admin admin) throws RemoteException;
    

      /**
       * Returns a certificateprofile id given it?s certificateprofilename.
       *
       * @return id number of certificateprofile.
       * @throws EJBException if a communication or other error occurs.
       */    
    public int getCertificateProfileId(Admin admin, String certificateprofilename) throws RemoteException;
    
       /**
       * Returns a certificateprofile name given it?s id.
       *
       * @return the name of certificateprofile.
       * @throws EJBException if a communication or other error occurs.
       */    
    public String getCertificateProfileName(Admin admin, int id) throws RemoteException;    
 
}
