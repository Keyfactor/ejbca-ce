
package se.anatom.ejbca.ca.store;

import java.util.Collection;
import java.util.Date;
import java.util.TreeMap;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.store.certificateprofiles.*;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: ICertificateStoreSessionLocal.java,v 1.9 2002-11-12 08:25:27 herrvendil Exp $
 * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
 */
public interface ICertificateStoreSessionLocal extends javax.ejb.EJBLocalObject, IPublisherSessionLocal {
 
   
    public final static int FIXED_CERTIFICATEPROFILE_BOUNDRY = ICertificateStoreSessionRemote.FIXED_CERTIFICATEPROFILE_BOUNDRY;    

    public final static int NO_CERTIFICATEPROFILE = LocalCertificateStoreSessionBean.NO_CERTIFICATEPROFILE;
    
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
    public Collection findCertificatesByUsername(String username);   
    
    /**
    * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
    */    
    public String findUsernameByCertSerno(BigInteger serno);    
 
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
    public void setRevokeStatus(BigInteger serno, int reason);    

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */      
    public boolean checkIfAllRevoked(String username);    
      
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
    
    public boolean addCertificateProfile(String certificateprofilename, CertificateProfile certificateprofile);   
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public boolean cloneCertificateProfile(String originalcertificateprofilename, String newcertificateprofilename);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public void removeCertificateProfile(String certificateprofilename);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public boolean renameCertificateProfile(String oldcertificateprofilename, String newcertificateprofilename);   

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public boolean changeCertificateProfile(String certificateprofilename, CertificateProfile certificateprofile); 
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */  
    public Collection getCertificateProfileNames();
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */     
    public TreeMap getCertificateProfiles();
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */ 
    public CertificateProfile getCertificateProfile(String certificateprofilename);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */      
    public CertificateProfile getCertificateProfile(int id);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */         
    public int getNumberOfCertificateProfiles();
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public int getCertificateProfileId(String certificateprofilename);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public String getCertificateProfileName(int id);      

}

