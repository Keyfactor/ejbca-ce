
package se.anatom.ejbca.ca.store;

import java.util.Collection;
import java.util.Date;
import java.util.TreeMap;
import java.rmi.RemoteException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.store.certificatetypes.*;

/** The CertificateStoreSession is the primary storage
 * for certificates and CRL. The CA always puts certificates and CRLs in the
 * CertificateStoreSession session bean defined in ca/ejb-jar.xml. The
 * CertificateStoreSession is also used to retrieve and find certificates,
 * retrieve CRLs, check for revocation etc. the CertificateStoreSession implements
 * the interface ICertificateStoreSession.
 *
 * Remote interface for EJB.
 *
 * @version $Id: ICertificateStoreSessionRemote.java,v 1.4 2002-08-27 12:41:06 herrvendil Exp $
 */
public interface ICertificateStoreSessionRemote extends javax.ejb.EJBObject, IPublisherSessionRemote  {
        
    /** Constants defining range of id's reserved for fixed certificate types. Observe fixed certificates cannot have value 0. */
    public final static int FIXED_CERTIFICATETYPE_BOUNDRY = 1000;

    public final static int FIXED_ENDUSER = LocalCertificateStoreSessionBean.FIXED_ENDUSER;
    public final static int FIXED_CA = LocalCertificateStoreSessionBean.FIXED_CA;
    public final static int FIXED_ROOTCA = LocalCertificateStoreSessionBean.FIXED_ROOTCA; 
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
    public Collection listAllCertificates() throws RemoteException;

   /**
    * Lists certificates for a given subject.
    *
    * @param subjectDN the DN of the subject whos certificates will be retrieved.
    * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection findCertificatesBySubject(String subjectDN) throws RemoteException;

   /**
    * Finds certificate for a given issuer and serialnumber.
    *
    * @param issuerDN the DN of the issuer.
    * @param serno the serialnumber of the certificate that will be retrieved
    * @return Certificate or null if none found.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate findCertificateByIssuerAndSerno(String issuerDN, BigInteger serno) throws RemoteException;

    /**
    * Finds certificate(s) for a given serialnumber.
    * @param serno the serialnumber of the certificate(s) that will be retrieved
    * @return Certificate or null if none found.
    *
    * @throws EJBException if a communication or other error occurs.
    *
    */
    public Collection findCertificatesBySerno(BigInteger serno) throws RemoteException;

   /**
    * Finds certificate which expire within a specified time.
    *
    * @param expireTime all certificates that expires before this date will be listed
    * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection findCertificatesByExpireTime(Date expireTime) throws RemoteException;
    
     /** 
     * Set the status of certificates of given dn to revoked.
     * @param dn the dn of user to revoke certificates.
     * @throws EJBException if a communication or other error occurs.
     */
    public void setRevokeStatus(String dn) throws RemoteException;

   /**
    * Checks if a certificate is revoked.
    *
    * @param issuerDN the DN of the issuer.
    * @param serno the serialnumber of the certificate that will be checked
    * @return null if certificate is NOT revoked, RevokedCertInfo if it IS revoked.
    * @throws EJBException if a communication or other error occurs.
    */
    public RevokedCertInfo isRevoked(String issuerDN, BigInteger serno) throws RemoteException;

    /**
    * Lists all revoked certificates, ie status = CERT_REVOKED.
    *
    * @return Collection of Strings containing fingerprint (primary key) of the revoced certificates. Reverse ordered by expireDate where last expireDate is first in array.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection listRevokedCertificates() throws RemoteException;

   /**
    * Retrieves the latest CRL issued by this CA.
    *
    * @return X509CRL or null of no CRLs have been issued.
    * @throws EJBException if a communication or other error occurs.
    */
    public byte[] getLastCRL() throws RemoteException;

   /**
    * Retrieves the highest CRLNumber issued by the CA.
    *
    * @return int.
    * @throws EJBException if a communication or other error occurs.
    */
    public int getLastCRLNumber() throws RemoteException;
    
    // Functions used for Certificate Types.
           
    /**
     * Adds a certificatetype to the database.
     *
     * @return false if certificatetypename already exists. 
     * @throws EJBException if a communication or other error occurs.
     */        
    
    public boolean addCertificateType(String certificatetypename, CertificateType certificatetype) throws RemoteException;   
    
     /**
     * Adds a certificatetype  with the same content as the original certificatetype, 
     *  
     * @return false if the new certificatetypename already exists.
     * @throws EJBException if a communication or other error occurs.     
     */ 
    public boolean cloneCertificateType(String originalcertificatetypename, String newcertificatetypename) throws RemoteException;
    
     /**
     * Removes a certificatetype from the database. 
     * 
     * @throws EJBException if a communication or other error occurs.   
     */ 
    public void removeCertificateType(String certificatetypename) throws RemoteException;
    
     /**
     * Renames a certificatetype.
     *
     * @return false if new name already exists
     * @throws EJBException if a communication or other error occurs.           
     */ 
    public boolean renameCertificateType(String oldcertificatetypename, String newcertificatetypename) throws RemoteException;   

    /**
     * Updates certificatetype data
     *
     * @return false if certificatetypename doesn't exists
     * @throws EJBException if a communication or other error occurs.
     */     
    
    public boolean changeCertificateType(String certificatetypename, CertificateType certificatetype) throws RemoteException; 
    
      /**
       * Returns the available certificatetype names.
       *
       * @return a collection of certificatetypenames.
       * @throws EJBException if a communication or other error occurs.
       */       
    public Collection getCertificateTypeNames() throws RemoteException;
      /**
       * Returns the available certificatetype.
       *
       * @return A collection of Profiles.
       * @throws EJBException if a communication or other error occurs.
       */        
    public TreeMap getCertificateTypes() throws RemoteException;
    
      /**
       * Returns the specified certificatetype.
       *
       * @return the certificatetype data or null if profile doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public CertificateType getCertificateType(String certificatetypename) throws RemoteException;
    
       /**
       * Returns the specified certificatetype.
       *
       * @return the certificatetype data or null if profile doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       */         
    public CertificateType getCertificateType(int id) throws RemoteException;

      /**
       * Returns the number of available certificatetypes.
       *
       * @return the number of available certificatetypes.
       * @throws EJBException if a communication or other error occurs.
       */             
    public int getNumberOfCertificateTypes() throws RemoteException;
    
      /**
       * Returns a certificatetype id given it´s certificatetypename.
       *
       * @return id number of certificatetype.
       * @throws EJBException if a communication or other error occurs.
       */    
    public int getCertificateTypeId(String certificatetypename) throws RemoteException;
    
       /**
       * Returns a certificatetype name given it´s id.
       *
       * @return the name of certificatetype.
       * @throws EJBException if a communication or other error occurs.
       */    
    public String getCertificateTypeName(int id) throws RemoteException;    
 
}
