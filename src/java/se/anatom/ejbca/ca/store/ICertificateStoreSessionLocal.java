package se.anatom.ejbca.ca.store;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.exception.CertificateProfileExistsException;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.log.Admin;


/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see ICertificateStoreSessionRemote for docs.
 *
 * @version $Id: ICertificateStoreSessionLocal.java,v 1.22 2003-12-04 10:20:48 anatom Exp $
 *
 * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
 */
public interface ICertificateStoreSessionLocal extends javax.ejb.EJBLocalObject,
    IPublisherSessionLocal {
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection listAllCertificates(Admin admin, String issuerdn);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection findCertificatesBySubjectAndIssuer(Admin admin, String subjectDN, String issuerDN);

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
    public String findUsernameByCertSerno(Admin admin, BigInteger serno, String issuerdn);    
 
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection findCertificatesByExpireTime(Admin admin, Date expireTime);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection findCertificatesByExpireTimeWithLimit(Admin admin, Date expiretime);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Certificate findCertificateByFingerprint(Admin admin, String fingerprint);

	/**
	 * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
	 */
	public Collection findCertificatesByIssuerAndSernos(Admin admin, String issuerDN, Collection sernos);

	/**
	 * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
	 */
	public Collection findCertificatesByType(Admin admin, int type, String issuerDN);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public RevokedCertInfo isRevoked(Admin admin, String issuerDN, BigInteger serno);

	/**
	 * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
	 */
	public Collection isRevoked(Admin admin, String issuerDN, Collection sernos);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public void setRevokeStatus(Admin admin, String username, int reason);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */ 
    public void setRevokeStatus(Admin admin, String issuerdn, BigInteger serno, int reason);  

	/**
	 * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
	 */    
	public void revokeAllCertByCA(Admin admin, String issuerdn, int reason); 

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public boolean checkIfAllRevoked(Admin admin, String username);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection listRevokedCertificates(Admin admin, String issuerdn);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public byte[] getLastCRL(Admin admin, String issuerdn);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public CRLInfo getLastCRLInfo(Admin admin, String issuerdn);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public int getLastCRLNumber(Admin admin, String issuerdn);
    
    // Functions used for Certificate Types.

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public void addCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile) throws CertificateProfileExistsException;

	/**
	 * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
	 */
	public void addCertificateProfile(Admin admin, int certificateprofileid, String certificateprofilename, 
		CertificateProfile certificateprofile) throws CertificateProfileExistsException;

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public void cloneCertificateProfile(Admin admin, String originalcertificateprofilename, String newcertificateprofilename) throws CertificateProfileExistsException;

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public void removeCertificateProfile(Admin admin, String certificateprofilename) ;

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public void renameCertificateProfile(Admin admin, String oldcertificateprofilename, String newcertificateprofilename) throws CertificateProfileExistsException;

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public void changeCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public Collection getAuthorizedCertificateProfileIds(Admin admin, int certprofiletype);
    
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public HashMap getCertificateProfileIdToNameMap(Admin admin);


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
    public int getCertificateProfileId(Admin admin, String certificateprofilename);

    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public String getCertificateProfileName(Admin admin, int id);
    
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote
     */
    public boolean existsCAInCertificateProfiles(Admin admin, int caid);       


}
