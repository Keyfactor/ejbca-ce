
package se.anatom.ejbca.ca.store;

import java.util.Collection;
import java.util.Date;
import java.util.TreeMap;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.store.certificatetypes.*;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: ICertificateStoreSessionLocal.java,v 1.7 2002-08-28 12:22:22 herrvendil Exp $
 * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
 */
public interface ICertificateStoreSessionLocal extends javax.ejb.EJBLocalObject, IPublisherSessionLocal {
 
   
    public final static int FIXED_CERTIFICATETYPE_BOUNDRY = ICertificateStoreSessionRemote.FIXED_CERTIFICATETYPE_BOUNDRY;    

    public final static int FIXED_ENDUSER = LocalCertificateStoreSessionBean.FIXED_ENDUSER;
    public final static int FIXED_CA = LocalCertificateStoreSessionBean.FIXED_CA;
    public final static int FIXED_ROOTCA = LocalCertificateStoreSessionBean.FIXED_ROOTCA; 
  
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection listAllCertificates();

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection findCertificatesBySubject(String subjectDN);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Certificate findCertificateByIssuerAndSerno(String issuerDN, BigInteger serno);

    /**
    * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
    */
    public Collection findCertificatesBySerno(BigInteger serno);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection findCertificatesByExpireTime(Date expireTime);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public RevokedCertInfo isRevoked(String issuerDN, BigInteger serno);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */    
    public void setRevokeStatus(String dn, int reason);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection listRevokedCertificates();

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public byte[] getLastCRL();

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public int getLastCRLNumber();
    
    // Functions used for Certificate Types.
           
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */    
    
    public boolean addCertificateType(String certificatetypename, CertificateType certificatetype);   
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public boolean cloneCertificateType(String originalcertificatetypename, String newcertificatetypename);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public void removeCertificateType(String certificatetypename);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public boolean renameCertificateType(String oldcertificatetypename, String newcertificatetypename);   

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public boolean changeCertificateType(String certificatetypename, CertificateType certificatetype); 
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */  
    public Collection getCertificateTypeNames();
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */     
    public TreeMap getCertificateTypes();
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */ 
    public CertificateType getCertificateType(String certificatetypename);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */      
    public CertificateType getCertificateType(int id);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */         
    public int getNumberOfCertificateTypes();
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public int getCertificateTypeId(String certificatetypename);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public String getCertificateTypeName(int id);      

}

