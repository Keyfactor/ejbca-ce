
package se.anatom.ejbca.ca.store;

import java.util.Collection;
import java.util.Date;
import java.util.TreeMap;
import java.math.BigInteger;
import java.security.cert.Certificate;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.store.certificateprofiles.*;
import se.anatom.ejbca.log.Admin;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: ICertificateStoreSessionLocal.java,v 1.12 2003-01-12 17:16:29 anatom Exp $
 * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
 */
public interface ICertificateStoreSessionLocal extends javax.ejb.EJBLocalObject, IPublisherSessionLocal {

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection listAllCertificates(Admin admin);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection findCertificatesBySubject(Admin admin, String subjectDN);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno);

    /**
    * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
    */

    public Collection findCertificatesBySerno(Admin admin, BigInteger serno);
    
    /**
    * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
    */

    public Collection findCertificatesByUsername(Admin admin, String username);   
    
    /**
    * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
    */    
    public String findUsernameByCertSerno(Admin admin, BigInteger serno);    
 
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection findCertificatesByExpireTime(Admin admin, Date expireTime);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public RevokedCertInfo isRevoked(Admin admin, String issuerDN, BigInteger serno);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */    
    public void setRevokeStatus(Admin admin, String dn, int reason);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */    
    public void setRevokeStatus(Admin admin, BigInteger serno, int reason);    


    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */      
    public boolean checkIfAllRevoked(Admin admin, String username);    
      
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection listRevokedCertificates(Admin admin);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public byte[] getLastCRL(Admin admin);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public int getLastCRLNumber(Admin admin);
    
    // Functions used for Certificate Types.

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */    
    
    public boolean addCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile);   
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public boolean cloneCertificateProfile(Admin admin, String originalcertificateprofilename, String newcertificateprofilename);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */

    public void removeCertificateProfile(Admin admin, String certificateprofilename);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */

    public boolean renameCertificateProfile(Admin admin, String oldcertificateprofilename, String newcertificateprofilename);   


    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public boolean changeCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile); 
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */  
    public Collection getCertificateProfileNames(Admin admin);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */     
    public TreeMap getCertificateProfiles(Admin admin);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */ 
    public CertificateProfile getCertificateProfile(Admin admin, String certificateprofilename);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */      
    public CertificateProfile getCertificateProfile(Admin admin, int id);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */         
    public int getNumberOfCertificateProfiles(Admin admin);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public int getCertificateProfileId(Admin admin, String certificateprofilename);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public String getCertificateProfileName(Admin admin, int id);      


}

