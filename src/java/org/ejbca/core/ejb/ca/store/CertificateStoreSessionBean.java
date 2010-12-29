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

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthenticationFailedException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.cvc.PublicKeyEC;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Stores certificate and CRL in the local database using Certificate and CRL Entity Beans.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateStoreSessionBean extends CertificateDataUtil implements CertificateStoreSessionRemote, CertificateStoreSessionLocal {

    private final static Logger log = Logger.getLogger(CertificateStoreSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private LogSessionLocal logSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    
    public CertificateStoreSessionBean() {
        super();
    }
    
    /**
     * Used by healthcheck. Validate database connection.
     * @return an error message or an empty String if all are ok.
     * 
     */
    public String getDatabaseStatus() {
		String returnval = "";
		try {
			entityManager.createNativeQuery(EjbcaConfiguration.getHealthCheckDbQuery()).getResultList();
			// TODO: Do we need to flush() the connection to avoid that this is executed in a batch after the method returns?
		} catch (Exception e) {
			returnval = "\nDB: Error creating connection to database: " + e.getMessage();
			log.error("Error creating connection to database.",e);
		}
		return returnval;
    }

    /**
     * Stores a certificate.
     *
     * @param incert   The certificate to be stored.
     * @param cafp     Fingerprint (hex) of the CAs certificate.
     * @param username username of end entity owning the certificate.
     * @param status   Status of the certificate (from CertificateData).
     * @param type     Type of certificate (CERTTYPE_ENDENTITY etc from CertificateDataBean).
     * @param certificateProfileId the certificate profile id this cert was issued under
     * @param tag a custom string tagging this certificate for some purpose
     * @return true if storage was successful.
     * @throws CreateException if the certificate can not be stored in the database
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean storeCertificate(Admin admin, Certificate incert, String username, String cafp,
                                    int status, int type, int certificateProfileId, String tag, long updateTime) throws CreateException {
    	if (log.isTraceEnabled()) {
            log.trace(">storeCertificate(" + username + ", " + cafp + ", " + status + ", " + type + ")");
    	}
        // Strip dangerous chars
        username = StringTools.strip(username);

        // We need special handling here of CVC certificate with EC keys, because they lack EC parameters in all certs except the Root certificate (CVCA)
    	PublicKey pubk = incert.getPublicKey();
    	if ((pubk instanceof PublicKeyEC)) {
    		PublicKeyEC pkec = (PublicKeyEC) pubk;
    		// The public key of IS and DV certificate (CVC) do not have any parameters so we have to do some magic to get a complete EC public key
    		ECParameterSpec spec = pkec.getParams();
    		if (spec == null) {
    			// We need to enrich this public key with parameters
    			try {
    				if (cafp != null) {
    					String cafingerp = cafp;
    					CertificateData cacert = CertificateData.findByFingerprint(entityManager, cafp);
    					if (cacert == null) {
    						throw new FinderException();
    					}
    					String nextcafp = cacert.getCaFingerprint();
    					int bar = 0; // never go more than 5 rounds, who knows what strange things can exist in the CAFingerprint column, make sure we never get stuck here
    					while ((!StringUtils.equals(cafingerp, nextcafp)) && (bar++ < 5)) {
        					cacert = CertificateData.findByFingerprint(entityManager, cafp);
        					if (cacert == null) {
        						throw new FinderException();
        					}
    						cafingerp = nextcafp;
    						nextcafp = cacert.getCaFingerprint();
    					}
						// We found a root CA certificate, hopefully ?
						PublicKey pkwithparams = cacert.getCertificate().getPublicKey();
						pubk = KeyTools.getECPublicKeyWithParams(pubk, pkwithparams);
    				}
				} catch (FinderException e) {
					log.info("Can not find CA certificate with fingerprint: "+cafp);
				} catch (Exception e) {
					// This catches NoSuchAlgorithmException, NoSuchProviderException and InvalidKeySpecException and possibly something else (NPE?)
					// because we want to continue anyway
					if (log.isDebugEnabled()) {
						log.debug("Can not enrich EC public key with missing parameters: ", e);
					}
				}
    		}
    	} // finished with ECC key special handling
    	
    	// Create the certificate in one go with all parameters at once. This used to be important in EJB2.1 so the persistence layer only creates *one* single
    	// insert statement. If we do a home.create and the some setXX, it will create one insert and one update statement to the database.
    	// Probably not important in EJB3 anymore
    	CertificateData data1 = new CertificateData(incert, pubk, username, cafp, status, type, certificateProfileId, tag, updateTime);
        try {
        	entityManager.persist(data1);
        } catch (Exception e) {
        	// For backward compatibility. We should drop the throw entirely and rely on the return value.
        	CreateException ce = new CreateException();
        	ce.setStackTrace(e.getStackTrace());
        	throw ce;
        }
        String msg = intres.getLocalizedMessage("store.storecert");            	
        logSession.log(admin, incert, LogConstants.MODULE_CA, new java.util.Date(), username, incert, LogConstants.EVENT_INFO_STORECERTIFICATE, msg);
        log.trace("<storeCertificate()");
        return true;
    }

    /**
     * Lists fingerprint (primary key) of ALL certificates in the database.
     * NOTE: Caution should be taken with this method as execution may be very
     * heavy indeed if many certificates exist in the database (imagine what happens if
     * there are millinos of certificates in the DB!).
     * Should only be used for testing purposes.
     *
     * @param admin    Administrator performing the operation
     * @param issuerdn the dn of the certificates issuer.
     * @return Collection of fingerprints, i.e. Strings.
     */
    public Collection<String> listAllCertificates(Admin admin, String issuerdn) {
    	log.trace(">listAllCertificates()");
    	// This method was only used from CertificateDataTest and it didn't care about the expireDate, so it will only select fingerprints now.
    	return CertificateData.findFingerprintsByIssuerDN(entityManager, CertTools.stringToBCDNString(StringTools.strip(issuerdn)));
    }

    /**
     * Lists RevokedCertInfo of ALL revoked certificates (status = CertificateDataBean.CERT_REVOKED) in the database from a certain issuer. 
     * NOTE: Caution should be taken with this method as execution may be very heavy indeed if many certificates exist in the database (imagine what happens if there are millinos of certificates in the DB!). 
     * Should only be used for testing purposes.
     * @param admin Administrator performing the operation
     * @param issuerdn the dn of the certificates issuer.
     * @param lastbasecrldate a date (Date.getTime()) of last base CRL or -1 for a complete CRL
     * @return Collection of RevokedCertInfo, reverse ordered by expireDate where last expireDate is first in array.
     */
    public Collection<RevokedCertInfo> listRevokedCertInfo(Admin admin, String issuerdn, long lastbasecrldate) {
    	log.trace(">listRevokedCertInfo()");
    	return CertificateData.getRevokedCertInfos(entityManager, CertTools.stringToBCDNString(StringTools.strip(issuerdn)), lastbasecrldate);
    }

    /**
     * Lists certificates for a given subject signed by the given issuer.
     *
     * @param admin     Administrator performing the operation
     * @param subjectDN the DN of the subject whos certificates will be retrieved.
     * @param issuerDN  the dn of the certificates issuer.
     * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
     */
    public Collection<Certificate> findCertificatesBySubjectAndIssuer(Admin admin, String subjectDN, String issuerDN) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "' and issuer='" + issuerDN + "'");
    	}
        // First make a DN in our well-known format
        String dn = StringTools.strip(subjectDN);
        dn = CertTools.stringToBCDNString(dn);
        String issuerdn = StringTools.strip(issuerDN);
        issuerdn = CertTools.stringToBCDNString(issuerdn);
        log.debug("Looking for cert with (transformed)DN: " + dn);
        Collection<Certificate> ret = new ArrayList<Certificate>();
        Collection<CertificateData> coll = CertificateData.findBySubjectDNAndIssuerDN(entityManager, dn, issuerdn);
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
        	ret.add(iter.next().getCertificate());
        }
        if (log.isTraceEnabled()) {
        	log.trace("<findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "' and issuer='" + issuerDN + "'");
        }
        return ret;
    }

    private Set<String> getSet(Collection<CertificateData> coll) {
        final Set<String> ret = new HashSet<String>();
        if (coll != null) {
            Iterator<CertificateData> iter = coll.iterator();
            while (iter.hasNext()) {
                ret.add(iter.next().getUsername());
            }
        }
        return ret;
    }
    /**
     * @param admin
     * @param issuerDN
     * @param subjectDN
     * @return set of users with certificates with specified subject DN issued by specified issuer.
     */
    public Set<String> findUsernamesByIssuerDNAndSubjectDN(Admin admin, String issuerDN, String subjectDN) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesBySubjectAndIssuer(), issuer='" + issuerDN + "'");
        }
        // First make a DN in our well-known format
        final String transformedIssuerDN = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        final String transformedSubjectDN = CertTools.stringToBCDNString(StringTools.strip(subjectDN));
        if ( log.isDebugEnabled() ) {
            log.debug("Looking for user with a certificate with issuer DN(transformed) '" + transformedIssuerDN + "' and subject DN(transformed) '"+transformedSubjectDN+"'.");
        }
        try {
            return getSet(CertificateData.findBySubjectDNAndIssuerDN(entityManager, transformedSubjectDN, transformedIssuerDN));
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<findCertificatesBySubjectAndIssuer(), issuer='" + issuerDN + "'");
            }
        }
    }

    /**
     * @param admin
     * @param issuerDN
     * @param subjectKeyId
     * @return set of users with certificates with specified key issued by specified issuer.
     */
    public Set<String> findUsernamesByIssuerDNAndSubjectKeyId(Admin admin, String issuerDN, byte subjectKeyId[]) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesBySubjectAndIssuer(), issuer='" + issuerDN + "'");
        }
        // First make a DN in our well-known format
        final String transformedIssuerDN = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        final String sSubjectKeyId = new String(Base64.encode(subjectKeyId, false));
        if ( log.isDebugEnabled() ) {
            log.debug("Looking for user with a certificate with issuer DN(transformed) '" + transformedIssuerDN + "' and SubjectKeyId '"+sSubjectKeyId+"'.");
        }
        try {
        	return getSet(CertificateData.findByIssuerDNAndSubjectKeyId(entityManager, transformedIssuerDN, sSubjectKeyId));
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<findCertificatesBySubjectAndIssuer(), issuer='" + issuerDN + "'");
            }
        }
    }

    /**
     * Lists certificates for a given subject.
     *
     * @param admin     Administrator performing the operation
     * @param subjectDN the DN of the subject whos certificates will be retrieved.
     * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
     */
    public Collection<Certificate> findCertificatesBySubject(Admin admin, String subjectDN) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "'");
    	}
        // First make a DN in our well-known format
        String dn = StringTools.strip(subjectDN);
        dn = CertTools.stringToBCDNString(dn);
        log.debug("Looking for cert with (transformed)DN: " + dn);
        Collection<Certificate> ret = new ArrayList<Certificate>();
        Collection<CertificateData> coll = CertificateData.findBySubjectDN(entityManager, dn);
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
        	ret.add(iter.next().getCertificate());
        }
        if (log.isTraceEnabled()) {
        	log.trace("<findCertificatesBySubject(), dn='" + subjectDN + "'");
        }
        return ret;
    }

    /**
     * Finds certificates  expiring within a specified time and that has
     * status "active" or "notifiedaboutexpiration".
     * @see org.ejbca.core.model.SecConst#CERT_ACTIVE
     * @see org.ejbca.core.model.SecConst#CERT_NOTIFIEDABOUTEXPIRATION
     * @return Collection of Certificate, never null
     */
    public Collection<Certificate> findCertificatesByExpireTimeWithLimit(Admin admin, Date expireTime) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesByExpireTime(), time=" + expireTime);
    	}
        // First make expiretime in well know format
        log.debug("Looking for certs that expire before: " + expireTime);
        Collection<CertificateData> coll = CertificateData.findByExpireDateWithLimit(entityManager, expireTime.getTime());
        Collection<Certificate> ret = new ArrayList<Certificate>();
        if (log.isDebugEnabled()) {
        	log.debug("Found "+coll.size()+" certificates that expire before "+expireTime);            		
        }
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
        	ret.add(iter.next().getCertificate());
        }
        if (log.isTraceEnabled()) {
        	log.trace("<findCertificatesByExpireTime(), time=" + expireTime);
        }
        return ret;
    }

    /**
     * Finds usernames of users having certificate(s) expiring within a specified time and that has
     * status "active" or "notifiedaboutexpiration".
     * @see org.ejbca.core.model.SecConst#CERT_ACTIVE
     * @see org.ejbca.core.model.SecConst#CERT_NOTIFIEDABOUTEXPIRATION
     * @return Collection of String, never null
     */
    public Collection<String>  findUsernamesByExpireTimeWithLimit(Admin admin, Date expiretime) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesByExpireTimeWithLimit: "+expiretime);    		
    	}
    	return CertificateData.findUsernamesByExpireTimeWithLimit(entityManager, new Date().getTime(), expiretime.getTime());
    }

    /**
     * Finds a certificate specified by issuer DN and serial number.
     *
     * @param admin    Administrator performing the operation
     * @param issuerDN issuer DN of the desired certificate.
     * @param serno    serial number of the desired certificate!
     * @return Certificate if found or null
     */
    public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno) {
    	return findCertificateByIssuerAndSerno(admin, issuerDN, serno, entityManager);
    }

    /**
     * Implements ICertificateStoreSession::findCertificatesByIssuerAndSernos.
     * <p/>
     * The method retrives all certificates from a specific issuer
     * which are identified by list of serial numbers. The collection
     * will be empty if the issuerDN is <tt>null</tt>/empty
     * or the collection of serial numbers is empty.
     *
     * @param admin
     * @param issuerDN the subjectDN of a CA certificate
     * @param sernos a Collection<BigInteger> of certificate serialnumbers
     * @return Collection a list of certificates; never <tt>null</tt>
     */
    public Collection<Certificate> findCertificatesByIssuerAndSernos(Admin admin, String issuerDN, Collection<BigInteger> sernos) {
    	log.trace(">findCertificateByIssuerAndSernos()");
        List<Certificate> ret = null;
        if (null == admin) {
            throw new IllegalArgumentException();	// TODO: Either check authorization properly or skip the Admin parameter.. this is just wrong..
        }
        if (null == issuerDN || issuerDN.length() <= 0 || null == sernos || sernos.isEmpty()) {
            ret = new ArrayList<Certificate>();
        } else {
            String dn = CertTools.stringToBCDNString(issuerDN);
            if (log.isDebugEnabled()) {
                log.debug("Looking for cert with (transformed)DN: " + dn);
            }
            ret = CertificateData.findCertificatesByIssuerDnAndSerialNumbers(entityManager, dn, sernos);
        }
        log.trace("<findCertificateByIssuerAndSernos()");
        return ret;
    }

    /**
     * Finds certificate(s) for a given serialnumber.
     *
     * @param admin Administrator performing the operation
     * @param serno the serialnumber of the certificate(s) that will be retrieved
     * @return Certificate or null if none found.
     */
    public Collection<Certificate> findCertificatesBySerno(Admin admin, BigInteger serno) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesBySerno(),  serno=" + serno);
    	}
    	ArrayList<Certificate> ret = new ArrayList<Certificate>();
    	Collection<CertificateData> coll = CertificateData.findBySerialNumber(entityManager, serno.toString());
    	Iterator<CertificateData> iter = coll.iterator();
    	while (iter.hasNext()) {
    		ret.add(iter.next().getCertificate());
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<findCertificatesBySerno(), serno=" + serno);
    	}
    	return ret;
    }

    /**
     * Finds username for a given certificate serial number.
     *
     * @param admin Administrator performing the operation
     * @param serno the serialnumber of the certificate to find username for.
     * @return username or null if none found.
     */
    public String findUsernameByCertSerno(Admin admin, BigInteger serno, String issuerdn) {
    	if (log.isTraceEnabled()) {
    		log.trace(">findUsernameByCertSerno(), serno: " + serno.toString(16) + ", issuerdn: " + issuerdn);    		
    	}
        String dn = CertTools.stringToBCDNString(issuerdn);
        Collection<CertificateData> coll = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
        String ret = null;
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
        	ret = iter.next().getUsername();
        }
        if (log.isTraceEnabled()) {
        	log.trace("<findUsernameByCertSerno(), ret=" + ret);
        }
        return ret;
    }

    /**
     * Finds certificate(s) for a given username.
     *
     * @param admin Administrator performing the operation
     * @param username the username of the certificate(s) that will be retrieved
     * @return Collection of Certificates ordered by expire date, with last expire date first, or null if none found.
     */
    public Collection<Certificate> findCertificatesByUsername(Admin admin, String username) {
    	return findCertificatesByUsername(admin, username, entityManager);
    }

    /**
     * Finds certificate(s) for a given username and status.
     *
     * @param admin Administrator performing the operation
     * @param username the username of the certificate(s) that will be retrieved
     * @param status the status of the CertificateDataBean.CERT_ constants
     * @return Collection of Certificates ordered by expire date, with last expire date first, or empty list if user can not be found
     */
    public Collection<Certificate> findCertificatesByUsernameAndStatus(Admin admin, String username, int status) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesByUsername(),  username=" + username);
    	}
        ArrayList<Certificate> ret = new ArrayList<Certificate>();
        // Strip dangerous chars
        username = StringTools.strip(username);
        // This method on the entity bean does the ordering in the database
        Collection<CertificateData> coll = CertificateData.findByUsernameAndStatus(entityManager, username, status);
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
        	ret.add(iter.next().getCertificate());
        }
    	if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByUsername(), username=" + username);
    	}
        return ret;
    }

    /** Gets certificate info, which is basically all fields except the certificate itself. 
     * Note: this method should not be used within a transaction where the reading of this info might depend on something stored earlier in the transaction. 
     * This is because this method uses direct SQL.
     * 
     * @return CertificateInfo or null if certificate does not exist.
     */
    public CertificateInfo getCertificateInfo(Admin admin, String fingerprint) {
    	// TODO: Either enforce authorization check or drop the Admin parameter
    	if (log.isTraceEnabled()) {
    		log.trace(">getCertificateInfo(): "+fingerprint);
    	}
    	return CertificateData.getCertificateInfo(entityManager, fingerprint);
    }

    public Certificate findCertificateByFingerprint(Admin admin, String fingerprint) {
        return findCertificateByFingerprint(admin, fingerprint, entityManager);
    }

    /**
     * Lists all active (status = 20) certificates of a specific type and if
     * given from a specific issuer.
     * <p/>
     * The type is the bitwise OR value of the types listed
     * int {@link org.ejbca.core.ejb.ca.store.CertificateDataBean}:<br>
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
     * <p/>
     * Usage examples:<br>
     * <ol>
     * <li>Get all root CA certificates
     * <p/>
     * <code>
     * ...
     * ICertificateStoreSessionRemote itf = ...
     * Collection certs = itf.findCertificatesByType(adm,
     * CertificateDataBean.CERTTYPE_ROOTCA,
     * null);
     * ...
     * </code>
     * </li>
     * <li>Get all subordinate CA certificates for a specific
     * Root CA. It is assumed that the <tt>subjectDN</tt> of the
     * Root CA certificate is located in the variable <tt>issuer</tt>.
     * <p/>
     * <code>
     * ...
     * ICertificateStoreSessionRemote itf = ...
     * Certficate rootCA = ...
     * String issuer = rootCA.getSubjectDN();
     * Collection certs = itf.findCertificatesByType(adm,
     * CertificateDataBean.CERTTYPE_SUBCA,
     * issuer);
     * ...
     * </code>
     * </li>
     * <li>Get <b>all</b> CA certificates.
     * <p/>
     * <code>
     * ...
     * ICertificateStoreSessionRemote itf = ...
     * Collection certs = itf.findCertificatesByType(adm,
     * CertificateDataBean.CERTTYPE_SUBCA
     * + CERTTYPE_ROOTCA,
     * null);
     * ...
     * </code>
     * </li>
     * </ol>
     *
     * @param admin
     * @param issuerDN get all certificates issued by a specific issuer.
     *                 If <tt>null</tt> or empty return certificates regardless of
     *                 the issuer.
     * @param type     CERTTYPE_* types from CertificateDataBean
     * @throws IllegalArgumentException when admin is null or type is not one or more of of SecConst.CERTTYPE_SUBCA, SecConst.CERTTYPE_ENDENTITY, SecConst.CERTTYPE_ROOTCA
     * @return Collection Collection of Certificate, never <tt>null</tt>
     */
    public Collection<Certificate> findCertificatesByType(Admin admin, int type, String issuerDN) throws IllegalArgumentException {
        return findCertificatesByType(admin, type, issuerDN, entityManager);
    }

    /** Method that sets status CertificateDataBean.CERT_ARCHIVED on the certificate data, only used from CreateCRLSessionBean and for testing.
     * Can only be performed by an Admin.TYPE_INTERNALUSER. 
     * Normally ARCHIVED is set by the CRL creation job, after a certificate has expired and been added to a CRL 
     * (expired certificates that are revoked must be present on at least one CRL).
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void setArchivedStatus(Admin admin, String fingerprint) throws AuthorizationDeniedException {
    	if (admin.getAdminType() != Admin.TYPE_INTERNALUSER) {
    		throw new AuthorizationDeniedException("Unauthorized");
    	}
    	CertificateData rev = CertificateData.findByFingerprint(entityManager, fingerprint);
    	if (rev != null) {
    		rev.setStatus(SecConst.CERT_ARCHIVED);
    		if (log.isDebugEnabled()) {
    			log.debug("Set status ARCHIVED for certificate with fp: "+fingerprint+", revocation reason is: "+rev.getRevocationReason());
    		}
    	} else {
    		String msg = intres.getLocalizedMessage("store.errorcertinfo", fingerprint);            	
    		logSession.log(admin, 0, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_UNKNOWN, msg);
    		throw new EJBException(msg);
    	}
    }
    
    /**
     * Set the status of certificate with given serno to revoked, or unrevoked (re-activation).
     *
     * Re-activating (unrevoking) a certificate have two limitations.
     * 1. A password (for for example AD) will not be restored if deleted, only the certificate and certificate status and associated info will be restored
     * 2. ExtendedInformation, if used by a publisher will not be used when re-activating a certificate 
     *
     * The method leaves up to the caller to find the correct publishers and userDataDN.
     * 
     * @param admin      Administrator performing the operation
     * @param issuerdn   Issuer of certificate to be removed.
     * @param serno      the serno of certificate to revoke.
     * @param publishers and array of publiserids (Integer) of publishers to revoke the certificate in.
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate, the object could be taken from user data instead.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void setRevokeStatus(Admin admin, String issuerdn, BigInteger serno, Collection<Integer> publishers, int reason, String userDataDN) {
    	if (log.isTraceEnabled()) {
        	log.trace(">setRevokeStatus(),  issuerdn=" + issuerdn + ", serno=" + serno.toString(16)+", reason="+reason);
    	}
        try {
        	Certificate certificate = findCertificateByIssuerAndSerno(admin, issuerdn, serno);
	        setRevokeStatus(admin, certificate, publishers, reason, userDataDN);
        } catch (FinderException e) {
        	String msg = intres.getLocalizedMessage("store.errorfindcertserno", serno.toString(16));            	
            logSession.log(admin, issuerdn.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_REVOKEDCERT, msg);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
            log.trace("<setRevokeStatus(),  issuerdn=" + issuerdn + ", serno=" + serno.toString(16)+", reason="+reason);
    	}
    }

    /**
     * Helper method to set the status of certificate to revoked or active. Re-activating (unrevoking) a certificate have two limitations.
     * 1. A password (for for example AD) will not be restored if deleted, only the certificate and certificate status and associated info will be restored
     * 2. ExtendedInformation, if used by a publisher will not be used when re-activating a certificate 
     *
     * The method leaves up to the caller to find the correct publishers and userDataDN.
     * 
     * @param admin      Administrator performing the operation
     * @param certificate the certificate to revoke or activate.
     * @param publishers and array of publiserids (Integer) of publishers to revoke/re-publish the certificate in.
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate use object from user data instead.
     * @throws FinderException 
     */
    private void setRevokeStatus(Admin admin, Certificate certificate, Collection<Integer> publishers, int reason, String userDataDN) throws FinderException {
    	if (certificate == null) {
    		return;
    	}
    	if (log.isTraceEnabled()) {
        	log.trace(">private setRevokeStatus(Certificate),  issuerdn=" + CertTools.getIssuerDN(certificate) + ", serno=" + CertTools.getSerialNumberAsString(certificate));
    	}
    	CertificateData rev = CertificateData.findByFingerprint(entityManager, CertTools.getFingerprintAsString(certificate));
    	if (rev == null) {
    		throw new FinderException("No certificate with fingerprint " + CertTools.getFingerprintAsString(certificate));
    	}
    	String username = rev.getUsername();
    	String cafp = rev.getCaFingerprint();
    	int type = rev.getType();
    	Date now = new Date();
    	String serialNo = CertTools.getSerialNumberAsString(certificate); // for logging
    	
    	// A normal revocation
    	if ( (rev.getStatus() != SecConst.CERT_REVOKED) 
    			&& (reason != RevokedCertInfo.NOT_REVOKED) && (reason != RevokedCertInfo.REVOKATION_REASON_REMOVEFROMCRL) ) {
    		rev.setStatus(SecConst.CERT_REVOKED);
    		rev.setRevocationDate(now);
    		rev.setUpdateTime(now.getTime());
    		rev.setRevocationReason(reason);            	  
    		String msg = intres.getLocalizedMessage("store.revokedcert", Integer.valueOf(reason));            	
    		logSession.log(admin, certificate, LogConstants.MODULE_CA, new java.util.Date(), null, certificate, LogConstants.EVENT_INFO_REVOKEDCERT, msg);
    		// Revoke in all related publishers
    		publisherSession.revokeCertificate(admin, publishers, certificate, username, userDataDN, cafp, type, reason, now.getTime(), rev.getTag(), rev.getCertificateProfileId(), now.getTime());
            // Unrevoke, can only be done when the certificate was previously revoked with reason CertificateHold
    	} else if ( ((reason == RevokedCertInfo.NOT_REVOKED) || (reason == RevokedCertInfo.REVOKATION_REASON_REMOVEFROMCRL)) 
    			&& (rev.getRevocationReason() == RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD) ) {
    		// Only allow unrevocation if the certificate is revoked and the revocation reason is CERTIFICATE_HOLD
    		int status = SecConst.CERT_ACTIVE;
    		rev.setStatus(status);
    		long revocationDate = -1L; // A null Date to setRevocationDate will result in -1 stored in long column
    		rev.setRevocationDate(null);
    		rev.setUpdateTime(now.getTime());
    		int revocationReason = RevokedCertInfo.NOT_REVOKED;
    		rev.setRevocationReason(revocationReason);
    		// Republish the certificate if possible
    		// If it is not possible, only log error but continue the operation of not revoking the certificate
    		try {
    			// Republishing will not restore a password, for example in AD, it will only re-activate the certificate.
    			String password = null;
    			boolean published = publisherSession.storeCertificate(admin, publishers, certificate, username, password, userDataDN,
    					cafp, status, type, revocationDate, revocationReason, rev.getTag(), rev.getCertificateProfileId(), now.getTime(), null);
    			if ( !published ) {
    				throw new Exception("Unrevoked cert:" + serialNo + " reason: " + reason + " Could not be republished.");
    			}                	  
    			String msg = intres.getLocalizedMessage("store.republishunrevokedcert", Integer.valueOf(reason));            	
    			logSession.log(admin, CertTools.getIssuerDN(certificate).hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, certificate, LogConstants.EVENT_INFO_NOTIFICATION, msg);
    		} catch (Exception ex) {
    			// We catch the exception thrown above, to log the message, but it is only informational, so we dont re-throw anything
    			logSession.log(admin, CertTools.getIssuerDN(certificate).hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, certificate, LogConstants.EVENT_INFO_NOTIFICATION, ex.getMessage());
    		}
    	} else {
    		String msg = intres.getLocalizedMessage("store.ignorerevoke", serialNo, Integer.valueOf(rev.getStatus()), Integer.valueOf(reason));            	
    		logSession.log(admin, CertTools.getIssuerDN(certificate).hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, certificate, LogConstants.EVENT_INFO_NOTIFICATION, msg);
    	}
    	if (log.isTraceEnabled()) {
        	log.trace("<private setRevokeStatus(),  issuerdn=" + CertTools.getIssuerDN(certificate) + ", serno=" + CertTools.getSerialNumberAsString(certificate));
    	}
    }

    /**
     * Revokes a certificate (already revoked by the CA), in the database. Also handles re-activation of suspended certificates.
     *
     * Re-activating (unrevoking) a certificate have two limitations.
     * 1. A password (for for example AD) will not be restored if deleted, only the certificate and certificate status and associated info will be restored
     * 2. ExtendedInformation, if used by a publisher will not be used when re-activating a certificate 
     * 
     * The method leaves up to the caller to find the correct publishers and userDataDN.
     *
     * @param admin      Administrator performing the operation
     * @param cert       The DER coded Certificate that has been revoked.
     * @param publishers and array of publiserids (Integer) of publishers to revoke the certificate in.
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate use object from user data instead.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void revokeCertificate(Admin admin, Certificate cert, Collection<Integer> publishers, int reason, String userDataDN) {
        if (cert instanceof X509Certificate) {
            setRevokeStatus(admin, CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert), publishers, reason, userDataDN);
        }
    }

    /**
     * Method revoking all certificates generated by the specified issuerdn. Sets revocationDate to current time.
     * Should only be called by CAAdminBean when a CA is about to be revoked.
     * 
     * TODO: Does not publish revocations to publishers!!!
     *
     * @param admin    the administrator performing the event.
     * @param issuerdn the dn of CA about to be revoked
     * @param reason   the reason of revocation.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void revokeAllCertByCA(Admin admin, String issuerdn, int reason) {
    	// TODO: Enforce or drop Admin parameter
        int temprevoked = 0;
        int revoked = 0;
        String bcdn = CertTools.stringToBCDNString(issuerdn);
        try {
            // Change all temporaty revoked certificates to permanently revoked certificates
        	temprevoked = CertificateData.revokeOnHoldPermanently(entityManager, bcdn);
            // Revoking all non revoked certificates.
        	revoked = CertificateData.revokeAllNonRevokedCertificates(entityManager, bcdn, reason);
    		String msg = intres.getLocalizedMessage("store.revokedallbyca", issuerdn, Integer.valueOf(revoked + temprevoked), Integer.valueOf(reason));            	
            logSession.log(admin, bcdn.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_REVOKEDCERT, msg);
        } catch (Exception e) {
    		String msg = intres.getLocalizedMessage("store.errorrevokeallbyca", issuerdn);            	
            logSession.log(admin, bcdn.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_REVOKEDCERT, msg, e);
            throw new EJBException(e);
        }
    }

    /**
     * Method that checks if a users all certificates have been revoked.
     *
     * @param admin    Administrator performing the operation
     * @param username the username to check for.
     * @return returns true if all certificates are revoked.
     */
    public boolean checkIfAllRevoked(Admin admin, String username) {
        boolean returnval = true;
        Certificate certificate = null;
        // Strip dangerous chars
        username = StringTools.strip(username);
        Collection<Certificate> certs = findCertificatesByUsername(admin, username);
        // Revoke all certs
        if (!certs.isEmpty()) {
        	Iterator<Certificate> j = certs.iterator();
        	while (j.hasNext()) {
        		certificate = j.next();
        		String fingerprint = CertTools.getFingerprintAsString(certificate);
        		CertificateInfo info = getCertificateInfo(admin, fingerprint);
        		if (info != null && info.getStatus() != SecConst.CERT_REVOKED) {
        			returnval = false;
        			break;
        		}
        	}
        }
        return returnval;
    }

    /**
     * Checks if a certificate is revoked.
     *
     * @param issuerDN the DN of the issuer.
     * @param serno    the serialnumber of the certificate that will be checked
     * @return true if the certificate is revoked or can not be found in the database, false if it exists and is not revoked.
     */
    public boolean isRevoked(String issuerDN, BigInteger serno) {
        if (log.isTraceEnabled()) {
        	log.trace(">isRevoked(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        boolean ret = false;
        try {
        	Collection<CertificateData> coll = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
            if (coll.size() > 0) {
                if (coll.size() > 1) {
                    String msg = intres.getLocalizedMessage("store.errorseveralissuerserno", issuerDN, serno.toString(16));             
                    //adapter.log(admin, issuerDN.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_DATABASE, msg);
                    log.error(msg);
                }
                Iterator<CertificateData> iter = coll.iterator();
                while (iter.hasNext()) {
                    CertificateData data = iter.next();
                    // if any of the certificates with this serno is revoked, return true
                    if (data.getStatus() == SecConst.CERT_REVOKED) {
                    	ret = true;
                    	break;
                    }
                }
            } else {
                // If there are no certificates with this serial number, return true (=revoked). Better safe than sorry!
            	ret = true;
            	if (log.isTraceEnabled()) {
            		log.trace("isRevoked() did not find certificate with dn "+dn+" and serno "+serno.toString(16));
            	}
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<isRevoked() returned " + ret);
        }
        return ret;
    }

    /**
     * Get certificate status fast.
     * 
     * @param issuerDN
     * @param serno
     * @return CertificateStatus status of the certificate, never null, CertificateStatus.NOT_AVAILABLE if the certificate is not found.
     */
    public CertificateStatus getStatus(String issuerDN, BigInteger serno) {
        return getStatus(issuerDN, serno, entityManager);
    }

    /**
     * Method that authenticates a certificate by checking validity and lookup if certificate is revoked.
     *
     * @param certificate the certificate to be authenticated.
     * @param requireAdminCertificateInDatabase if true the certificate has to exist in the database
     * @throws AuthenticationFailedException if authentication failed.
     */
    public void authenticate(X509Certificate certificate, boolean requireAdminCertificateInDatabase) throws AuthenticationFailedException {
        // Check Validity
        try {
            certificate.checkValidity();
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("authentication.certexpired", CertTools.getNotAfter(certificate).toString());            	
            throw new AuthenticationFailedException(msg);
        }
        if (requireAdminCertificateInDatabase) {
            // TODO: Verify Signature on cert? Not really needed since it's one of ou certs in the database.
            // Check if certificate is revoked.
            boolean isRevoked = isRevoked(CertTools.getIssuerDN(certificate),CertTools.getSerialNumber(certificate));
            if (isRevoked) {
                // Certificate revoked or missing in the database
            	String msg = intres.getLocalizedMessage("authentication.revokedormissing");            	
                throw new AuthenticationFailedException(msg);
            }
        } else {
        	// TODO: We should check the certificate for CRL or OCSP tags and verify the certificate status
        }
    }

    /**
     * Method used to add a CertReqHistory to database
     * 
     * @param admin calling the methods
     * @param cert the certificate to store (Only X509Certificate used for now)
     * @param useradmindata the user information used when issuing the certificate.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void addCertReqHistoryData(Admin admin, Certificate cert, UserDataVO useradmindata){
    	if (log.isTraceEnabled()) {
        	log.trace(">addCertReqHistoryData(" + CertTools.getSerialNumberAsString(cert) + ", " + CertTools.getIssuerDN(cert) + ", " + useradmindata.getUsername() + ")");
    	}
        try {
        	entityManager.persist(new CertReqHistoryData(cert, useradmindata));
        	String msg = intres.getLocalizedMessage("store.storehistory", useradmindata.getUsername());            	
            logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), useradmindata.getUsername(), cert, LogConstants.EVENT_INFO_STORECERTIFICATE, msg);            
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("store.errorstorehistory", useradmindata.getUsername());            	
            logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), useradmindata.getUsername(), cert, LogConstants.EVENT_ERROR_STORECERTIFICATE, msg);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<addCertReqHistoryData()");
        }
    }
    
    /**
     * Method to remove CertReqHistory data.
     * @param admin
     * @param certFingerprint the primary key.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeCertReqHistoryData(Admin admin, String certFingerprint){
    	if (log.isTraceEnabled()) {
        	log.trace(">removeCertReqHistData(" + certFingerprint + ")");
    	}
        try {          
        	String msg = intres.getLocalizedMessage("store.removehistory", certFingerprint);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_STORECERTIFICATE, msg);
            entityManager.remove(CertReqHistoryData.findById(entityManager, certFingerprint));
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("store.errorremovehistory", certFingerprint);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECERTIFICATE, msg);
            throw new EJBException(e);
        }
        log.trace("<removeCertReqHistData()");       	
    }
    
    /**
     * Retrieves the certificate request data belonging to given certificate serialnumber and issuerdn
     * 
     * @param admin
     * @param certificateSN serial number of the certificate
     * @param issuerDN
     * @return the CertReqHistory or null if no data is stored with the certificate.
     */
    public CertReqHistory getCertReqHistory(Admin admin, BigInteger certificateSN, String issuerDN){
    	CertReqHistory retval = null;
    	Collection<CertReqHistoryData> result = CertReqHistoryData.findByIssuerDNSerialNumber(entityManager, issuerDN, certificateSN.toString());
    	if(result.iterator().hasNext()) {
    		retval = result.iterator().next().getCertReqHistory();
    	}
    	return retval;
    }

    /**
     * Retrieves all cert request datas belonging to a user.
     * @param admin
     * @param username
     * @return a collection of CertReqHistory
     */
    public List<CertReqHistory> getCertReqHistory(Admin admin, String username){
    	ArrayList<CertReqHistory> retval = new ArrayList<CertReqHistory>();
    	Collection<CertReqHistoryData> result = CertReqHistoryData.findByUsername(entityManager, username);
    	Iterator<CertReqHistoryData> iter = result.iterator();
    	while(iter.hasNext()) {
    		retval.add(iter.next().getCertReqHistory());
    	}
    	return retval;
    }
    
    /**
     * Fetch a List of all certificate fingerprints and corresponding username
     * @return [0] = (String) fingerprint, [1] = (String) username
     */
    public List<Object[]> findExpirationInfo(String cASelectString, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax, long activeExpireDateMin) {
    	return CertificateData.findExpirationInfo(entityManager, cASelectString, activeNotifiedExpireDateMin, activeNotifiedExpireDateMax, activeExpireDateMin);
    }

    /**
     * Update the staus of a cert in the database.
     * @param fingerprint
     * @param status one of SecConst.CERT_...
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setStatus(String fingerprint, int status) {
    	return CertificateData.updateStatus(entityManager, fingerprint, status);
    }
}
