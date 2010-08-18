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
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
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
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.ProtectConfiguration;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CertificateProfileData;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.protect.TableProtectSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthenticationFailedException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.certificateprofiles.CACertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenAuthCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenAuthEncCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenEncCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenSignCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.OCSPSignerCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.RootCACertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.ServerCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.protect.TableVerifyResult;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.cvc.PublicKeyEC;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.StringTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Stores certificate and CRL in the local database using Certificate and CRL Entity Beans.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @ejb.bean display-name="CertificateStoreSB"
 * name="CertificateStoreSession"
 * jndi-name="CertificateStoreSession"
 * view-type="both"
 * type="Stateless"
 * transaction-type="Container"
 *
 * @ejb.transaction type="Supports"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry description="JDBC datasource to be used"
 * name="DataSource"
 * type="java.lang.String"
 * value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 * @ejb.ejb-external-ref description="The Certificate entity bean used to store and fetch certificates"
 * view-type="local"
 * ref-name="ejb/CertificateDataLocal"
 * type="Entity"
 * home="org.ejbca.core.ejb.ca.store.CertificateDataLocalHome"
 * business="org.ejbca.core.ejb.ca.store.CertificateDataLocal"
 * link="CertificateData"
 *
 * @ejb.ejb-external-ref description="The CertReqHistoryData Entity bean"
 * view-type="local"
 * ref-name="ejb/CertReqHistoryDataLocal"
 * type="Entity"
 * home="org.ejbca.core.ejb.ca.store.CertReqHistoryDataLocalHome"
 * business="org.ejbca.core.ejb.ca.store.CertReqHistoryDataLocal"
 * link="CertReqHistoryData"
 *
 * @ejb.ejb-external-ref description="The CertificateProfileData Entity bean"
 * view-type="local"
 * ref-name="ejb/CertificateProfileDataLocal"
 * type="Entity"
 * home="org.ejbca.core.ejb.ca.store.CertificateProfileDataLocalHome"
 * business="org.ejbca.core.ejb.ca.store.CertificateProfileDataLocal"
 * link="CertificateProfileData"
 * 
 * @ejb.ejb-external-ref description="The Log session bean"
 * view-type="local"
 * ref-name="ejb/LogSessionLocal"
 * type="Session"
 * home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 * business="org.ejbca.core.ejb.log.ILogSessionLocal"
 * link="LogSession"
 *
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *
 * @ejb.ejb-external-ref description="The Authorization session bean"
 * view-type="local"
 * ref-name="ejb/AuthorizationSessionLocal"
 * type="Session"
 * home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 * business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 * link="AuthorizationSession"
 *
 * @ejb.ejb-external-ref description="Publishers are configured to store certificates and CRLs in additional places from the main database.
 * Publishers runs as local beans"
 * view-type="local"
 * ref-name="ejb/PublisherSessionLocal"
 * type="Session"
 * home="org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome"
 * business="org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal"
 * link="PublisherSession"
 *
 * @ejb.ejb-external-ref
 *   description="The table protection session bean"
 *   view-type="local"
 *   ref-name="ejb/TableProtectSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.protect.TableProtectSessionLocalHome"
 *   business="org.ejbca.core.ejb.protect.TableProtectSessionLocal"
 *   link="TableProtectSession"
 *   
 * @ejb.home extends="javax.ejb.EJBHome"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 * remote-class="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 * remote-class="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote"
 * 
 * @jboss.method-attributes
 *   pattern = "get*"
 *   read-only = "true"
 *
 * @jboss.method-attributes
 *   pattern = "find*"
 *   read-only = "true"
 *   
 * @jboss.method-attributes
 *   pattern = "list*"
 *   read-only = "true"
 *   
 * @jboss.method-attributes
 *   pattern = "is*"
 *   read-only = "true"
 *   
 * @jboss.method-attributes
 *   pattern = "exists*"
 *   read-only = "true"
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class LocalCertificateStoreSessionBean  implements CertificateStoreSessionRemote, CertificateStoreSessionLocal {

    private final static Logger log = Logger.getLogger(LocalCertificateStoreSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private LogSessionLocal logSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private TableProtectSessionLocal tableProtectSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    
    /** If protection of database entries are enabled of not, default not */
    private boolean protect = ProtectConfiguration.getCertProtectionEnabled();

    final private CertificateDataUtil.Adapter adapter;
    
    public LocalCertificateStoreSessionBean() {
        super();
        adapter = new MyAdapter();
    }
    
    /**
     * Used by healthcheck. Validate database connection.
     * @return an error message or an empty String if all are ok.
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="local"
     */
    public String getDatabaseStatus() {
		String returnval = "";
		Connection con = null;
		try {
		  con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
		  Statement statement = con.createStatement();
		  statement.execute(EjbcaConfiguration.getHealthCheckDbQuery());		  
		} catch (Exception e) {
			returnval = "\nDB: Error creating connection to database: " + e.getMessage();
			log.error("Error creating connection to database.",e);
		} finally {
			JDBCUtil.close(con);
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
     * @ejb.transaction type="Required"
     * @ejb.interface-method
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
    	
    	CertificateData data1 = new CertificateData(incert, pubk);
    	String data1Fingerprint = data1.getFingerprint();
        data1.setUsername(username);
        data1.setCaFingerprint(cafp);
        data1.setStatus(status);
        data1.setType(type);
        data1.setCertificateProfileId(certificateProfileId);
        data1.setTag(tag);
        data1.setUpdateTime(updateTime);
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
        if (protect) {
        	CertificateInfo entry = new CertificateInfo(data1Fingerprint, cafp, data1.getSerialNumber(), data1.getIssuerDN(), data1.getSubjectDN(), status, type, data1.getExpireDate(), data1.getRevocationDate(), data1.getRevocationReason(), username, tag, certificateProfileId, updateTime);
        	tableProtectSession.protect(entry);
        }
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
     * @return Collection of fingerprints, i.e. Strings, reverse ordered by expireDate where last expireDate is first in array.
     * @ejb.interface-method
     */
    public Collection listAllCertificates(Admin admin, String issuerdn) {
    	log.trace(">listAllCertificates()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        String dn = CertTools.stringToBCDNString(StringTools.strip(issuerdn));
        try {
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select fingerprint, expireDate from CertificateData where issuerDN=? ORDER BY expireDate DESC");
            ps.setString(1, dn);
            result = ps.executeQuery();
            ArrayList<String> vect = new ArrayList<String>();
            while (result.next()) {
                vect.add(result.getString(1));
            }
            log.trace("<listAllCertificates()");
            return vect;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
    }

    /**
     * Lists RevokedCertInfo of ALL revoked certificates (status = CertificateDataBean.CERT_REVOKED) in the database from a certain issuer. 
     * NOTE: Caution should be taken with this method as execution may be very heavy indeed if many certificates exist in the database (imagine what happens if there are millinos of certificates in the DB!). 
     * Should only be used for testing purposes.
     * @param admin Administrator performing the operation
     * @param issuerdn the dn of the certificates issuer.
     * @param lastbasecrldate a date (Date.getTime()) of last base CRL or -1 for a complete CRL
     * @return Collection of RevokedCertInfo, reverse ordered by expireDate where last expireDate is first in array.
     *
     * @ejb.interface-method
     */
    public Collection listRevokedCertInfo(Admin admin, String issuerdn, long lastbasecrldate) {
    	log.trace(">listRevokedCertInfo()");

    	Connection con = null;
    	PreparedStatement ps = null;
    	ResultSet result = null;
    	String dn = CertTools.stringToBCDNString(StringTools.strip(issuerdn));
    	try {
    		// TODO:
    		// This should only list a few thousand certificates at a time, in case there
    		// are really many revoked certificates after some time...
    		con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
    		String sql = "select fingerprint, serialNumber, expireDate, revocationDate, revocationReason from CertificateData where issuerDN=? and status=?";
    		// For delta CRLs we must select both revoked certificates, and certificates that are active because they have been un-revoked
    		String deltaCRLSql = "select fingerprint, serialNumber, expireDate, revocationDate, revocationReason from CertificateData where issuerDN=? and revocationDate>? and (status=? or (status=? and revocationReason=?))";
    		if (lastbasecrldate > 0) {
    			sql = deltaCRLSql;
    		}
    		if (log.isDebugEnabled()) {
        		log.debug("Executing SQL: "+sql);    			
    		}
    		ps = con.prepareStatement(sql);
    		ps.setString(1, dn);
    		if (lastbasecrldate > 0) {
    			ps.setLong(2, lastbasecrldate);
    			ps.setInt(3, SecConst.CERT_REVOKED);
    			ps.setInt(4, SecConst.CERT_ACTIVE);
    			ps.setInt(5, RevokedCertInfo.REVOKATION_REASON_REMOVEFROMCRL);
    		} else {
    			ps.setInt(2, SecConst.CERT_REVOKED);            	
    		}
    		result = ps.executeQuery();
    		log.trace("listRevokedCertInfo(): query done");
    		ArrayList<RevokedCertInfo> vect = new ArrayList<RevokedCertInfo>();
    		while (result.next()) {
    			String fp = result.getString(1);
    			BigInteger serNo = new BigInteger(result.getString(2));
    			long exptime = result.getLong(3);
    			Date expDate = null;
    			if (exptime > 0) {
    				expDate = new Date(exptime);
    			}
    			long revtime = result.getLong(4);
    			Date revDate = null;
    			if (revtime > 0) {
    				revDate = new Date(revtime);            	
    			}
    			int revReason = result.getInt(5);
    			RevokedCertInfo certinfo = new RevokedCertInfo(fp, serNo, revDate, revReason, expDate);
    			// Add to the result
    			vect.add(certinfo);
    		}
    		log.trace("<listRevokedCertInfo()");
    		return vect;
    	} catch (Exception e) {
    		throw new EJBException(e);
    	} finally {
    		JDBCUtil.close(con, ps, result);
    	}
    }

    /**
     * Lists certificates for a given subject signed by the given issuer.
     *
     * @param admin     Administrator performing the operation
     * @param subjectDN the DN of the subject whos certificates will be retrieved.
     * @param issuerDN  the dn of the certificates issuer.
     * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method
     */
    public Collection findCertificatesBySubjectAndIssuer(Admin admin, String subjectDN, String issuerDN) {
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
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method
     */
    public Set findUsernamesByIssuerDNAndSubjectDN(Admin admin, String issuerDN, String subjectDN) {
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
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method
     */
    public Set findUsernamesByIssuerDNAndSubjectKeyId(Admin admin, String issuerDN, byte subjectKeyId[]) {
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
     * @ejb.interface-method
     */
    public Collection findCertificatesBySubject(Admin admin, String subjectDN) {
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
     * @ejb.interface-method
     */
    public Collection findCertificatesByExpireTime(Admin admin, Date expireTime) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesByExpireTime(), time=" + expireTime);
    	}
        // First make expiretime in well know format
        log.debug("Looking for certs that expire before: " + expireTime);
        Collection<CertificateData> coll = CertificateData.findByExpireDate(entityManager, expireTime.getTime());
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
     *
     * @ejb.interface-method
     */
    public Collection findCertificatesByExpireTimeWithLimit(Admin admin, Date expiretime) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesByExpireTimeWithLimit: "+expiretime);    		
    	}
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        ArrayList<String> returnval = new ArrayList<String>();
        long currentdate = new Date().getTime();
        try {
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("SELECT DISTINCT username FROM CertificateData WHERE expireDate>=? AND expireDate<? AND (status=? OR status=?)");
            ps.setLong(1, currentdate);
            ps.setLong(2, expiretime.getTime());
            ps.setInt(3, SecConst.CERT_ACTIVE);
            ps.setInt(4, SecConst.CERT_NOTIFIEDABOUTEXPIRATION);
            result = ps.executeQuery();
            while (result.next() && returnval.size() <= SecConst.MAXIMUM_QUERY_ROWCOUNT + 1) {
                if (result.getString(1) != null && !result.getString(1).equals("")) {
                    returnval.add(result.getString(1));
                }
            }
        	if (log.isTraceEnabled()) {
        		log.trace("<findCertificatesByExpireTimeWithLimit()");
        	}
            return returnval;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
    }

    /**
     * Finds a certificate specified by issuer DN and serial number.
     *
     * @param admin    Administrator performing the operation
     * @param issuerDN issuer DN of the desired certificate.
     * @param serno    serial number of the desired certificate!
     * @return Certificate if found or null
     * @ejb.interface-method
     */
    public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno) {
    	return CertificateDataUtil.findCertificateByIssuerAndSerno(admin, issuerDN, serno, entityManager, adapter);
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
     * @ejb.interface-method
     */
    public Collection findCertificatesByIssuerAndSernos(Admin admin, String issuerDN, Collection sernos) {
    	log.trace(">findCertificateByIssuerAndSernos()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        ArrayList<Certificate> vect = null;
        if (null == admin) {
            throw new IllegalArgumentException();
        }
        if (null == issuerDN || issuerDN.length() <= 0
                || null == sernos || sernos.isEmpty()) {
            return new ArrayList<Certificate>();
        }
        String dn = CertTools.stringToBCDNString(issuerDN);
        log.debug("Looking for cert with (transformed)DN: " + dn);
        try {
            final StringBuffer sb = new StringBuffer();
            {
                Iterator<BigInteger> iter = sernos.iterator();
                while (iter.hasNext()) {
                    sb.append(", '");
                    // Make sure this is really a BigInteger passed in as (untrusted param)
                    BigInteger serno = iter.next();
                    sb.append(serno.toString());
                    sb.append("'");
                }
            }
            /*
             * to save the repeating if-statement in the above
             * Closure not to add ', ' as the first characters
             * in the StringBuffer we remove the two chars here :)
             */
            sb.delete(0, ", ".length());
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("SELECT DISTINCT fingerprint"
                    + " FROM CertificateData WHERE"
                    + " issuerDN = ?"
                    + " AND serialNumber IN (" + sb.toString() + ")");
            ps.setString(1, dn);
            result = ps.executeQuery();
            vect = new ArrayList<Certificate>();
            while (result.next()) {
                Certificate cert = findCertificateByFingerprint(admin, result.getString(1));
                if (cert != null) {
                    vect.add(cert);
                }
            }
            log.trace("<findCertificateByIssuerAndSernos()");
            return vect;
        } catch (Exception fe) {
            throw new EJBException(fe);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
    }

    /**
     * Finds certificate(s) for a given serialnumber.
     *
     * @param admin Administrator performing the operation
     * @param serno the serialnumber of the certificate(s) that will be retrieved
     * @return Certificate or null if none found.
     * @ejb.interface-method
     */
    public Collection findCertificatesBySerno(Admin admin, BigInteger serno) {
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
     * @ejb.interface-method
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
     * @ejb.interface-method
     */
    public Collection findCertificatesByUsername(Admin admin, String username) {
    	return CertificateDataUtil.findCertificatesByUsername(admin, username, entityManager, adapter);
    }

    /**
     * Finds certificate(s) for a given username and status.
     *
     * @param admin Administrator performing the operation
     * @param username the username of the certificate(s) that will be retrieved
     * @param status the status of the CertificateDataBean.CERT_ constants
     * @return Collection of Certificates ordered by expire date, with last expire date first, or empty list if user can not be found
     * @ejb.interface-method
     */
    public Collection findCertificatesByUsernameAndStatus(Admin admin, String username, int status) {
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
     * Note: this methid should not be used within a transaction where the reading of this info might depend on something stored earlier in the transaction. 
     * This is because this method uses direct SQL.
     * 
     * @return CertificateInfo or null if certificate does not exist.
     * @ejb.interface-method
     */
    public CertificateInfo getCertificateInfo(Admin admin, String fingerprint) {
    	log.trace(">getCertificateInfo()");
        CertificateInfo ret = null;
        Connection con = null;
        ResultSet rs = null;
        PreparedStatement ps = null;
    	try {
            // Now go on with the real select
	    	con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
	    	StringBuilder sql = new StringBuilder();
	    	sql.append("select issuerDN,subjectDN,cAFingerprint,status,type,serialNumber,expireDate,revocationDate,revocationReason,username,tag,certificateProfileId,updateTime from CertificateData where fingerprint=?");
	    	if (log.isDebugEnabled()) {
	    		log.debug("Executing SQL: "+sql.toString());    			
			}
	    	ps = con.prepareStatement(sql.toString());
	    	ps.setString(1, fingerprint);
			rs = ps.executeQuery();
			// This query can only return one row (fingerprint is the primary key)
			if (rs.next()) {
				String cafp = rs.getString(3);
				String serno = rs.getString(6);
				String issuerDN = rs.getString(1);
				String subjectDN = rs.getString(2);
				int status = rs.getInt(4);
				int type = rs.getInt(5);
				long expireDate = rs.getLong(7);
				long revocationDate = rs.getLong(8);
				int revocationReason = rs.getInt(9);
				String username = rs.getString(10);
				String tag = rs.getString(11);
				int cProfId = rs.getInt(12);
				long updateTime = rs.getLong(13);
	            ret = new CertificateInfo(fingerprint, cafp, serno, issuerDN, subjectDN, status, 
	            		type, expireDate, revocationDate, revocationReason, username, tag, cProfId, updateTime);				
			}
        } catch (SQLException e) {
        	String msg = intres.getLocalizedMessage("store.errorcertinfo", fingerprint);            	
            log.error(msg);
            throw new EJBException(e);
        } finally {
        	JDBCUtil.close(con, ps, rs);
        }
        log.trace("<getCertificateInfo()");
        return ret;
    }

    /**
     * @ejb.interface-method
     */
    public Certificate findCertificateByFingerprint(Admin admin, String fingerprint) {
        return CertificateDataUtil.findCertificateByFingerprint(admin, fingerprint, entityManager, adapter);
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
     * @return Collection Collection of Certificate, never <tt>null</tt>
     * @ejb.interface-method
     */
    public Collection findCertificatesByType(Admin admin, int type, String issuerDN) {
        return CertificateDataUtil.findCertificatesByType(admin, type, issuerDN, entityManager, adapter);
    }

    /** Method that sets status CertificateDataBean.CERT_ARCHIVED on the certificate data, only used for testing.
     * Can only be performed by an Admin.TYPE_INTERNALUSER. 
     * Normally ARCHIVED is set by the CRL creation job, after a certificate has expired and been added to a CRL 
     * (expired certificates that are revoked must be present on at least one CRL).
     * @ejb.transaction type="Required"
     * @ejb.interface-method
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
     * @param reason     the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate, the object could be taken from user data instead.
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void setRevokeStatus(Admin admin, String issuerdn, BigInteger serno, Collection publishers, int reason, String userDataDN) {
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
     * @param reason     the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate use object from user data instead.
     * @throws FinderException 
     */
    private void setRevokeStatus(Admin admin, Certificate certificate, Collection publishers, int reason, String userDataDN) throws FinderException {
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
    		String msg = intres.getLocalizedMessage("store.revokedcert", new Integer(reason));            	
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
    			String msg = intres.getLocalizedMessage("store.republishunrevokedcert", new Integer(reason));            	
    			logSession.log(admin, CertTools.getIssuerDN(certificate).hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, certificate, LogConstants.EVENT_INFO_NOTIFICATION, msg);
    		} catch (Exception ex) {
    			// We catch the exception thrown above, to log the message, but it is only informational, so we dont re-throw anything
    			logSession.log(admin, CertTools.getIssuerDN(certificate).hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, certificate, LogConstants.EVENT_INFO_NOTIFICATION, ex.getMessage());
    		}
    	} else {
    		String msg = intres.getLocalizedMessage("store.ignorerevoke", serialNo, new Integer(rev.getStatus()), new Integer(reason));            	
    		logSession.log(admin, CertTools.getIssuerDN(certificate).hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, certificate, LogConstants.EVENT_INFO_NOTIFICATION, msg);
    	}
    	// Update database protection
    	if (protect) {
    		CertificateInfo entry = new CertificateInfo(rev.getFingerprint(), rev.getCaFingerprint(), rev.getSerialNumber(), rev.getIssuerDN(), rev.getSubjectDN(), rev.getStatus(), rev.getType(), rev.getExpireDate(), rev.getRevocationDate(), rev.getRevocationReason(), username, rev.getTag(), rev.getCertificateProfileId(), rev.getUpdateTime());
    		tableProtectSession.protect(entry);
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
     * @param reason     the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate use object from user data instead.
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void revokeCertificate(Admin admin, Certificate cert, Collection publishers, int reason, String userDataDN) {
        if (cert instanceof X509Certificate) {
            setRevokeStatus(admin, CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert), publishers, reason, userDataDN);
        }
    }

    /**
     * Method revoking all certificates generated by the specified issuerdn. Sets revokedate to current time.
     * Should only be called by CAAdminBean when a CA is about to be revoked.
     * 
     * TODO: Does not publish revocations to publishers!!!
     *
     * @param admin    the administrator performing the event.
     * @param issuerdn the dn of CA about to be revoked
     * @param reason   the reason of revokation.
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void revokeAllCertByCA(Admin admin, String issuerdn, int reason) {
        Connection con = null;
        PreparedStatement ps = null;
        PreparedStatement ps2 = null;
        int temprevoked = 0;
        int revoked = 0;

        String bcdn = CertTools.stringToBCDNString(issuerdn);

        final String firstsqlstatement = "UPDATE CertificateData SET status=?" +
                " WHERE issuerDN=? AND status = ? ";
        final String secondsqlstatement = "UPDATE CertificateData SET status=?, revocationDate=?, revocationReason=?" +
                " WHERE issuerDN=? AND status <> ?";

        long currentdate = new Date().getTime();

        try {
            // First SQL statement, changing all temporaty revoked certificates to permanently revoked certificates
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement(firstsqlstatement);
            ps.setInt(1, SecConst.CERT_REVOKED); // first statusfield
            ps.setString(2, bcdn); // issuerdn field
            ps.setInt(3, SecConst.CERT_TEMP_REVOKED); // second statusfield
            temprevoked = ps.executeUpdate();

            // Second SQL statement, revoking all non revoked certificates.
            ps2 = con.prepareStatement(secondsqlstatement);
            ps2.setInt(1, SecConst.CERT_REVOKED); // first statusfield
            ps2.setLong(2, currentdate); // revokedate field
            ps2.setInt(3, reason); // revokation reason
            ps2.setString(4, bcdn); // issuer dn
            ps2.setInt(5, SecConst.CERT_REVOKED); // second statusfield

            revoked = ps2.executeUpdate();

    		String msg = intres.getLocalizedMessage("store.revokedallbyca", issuerdn, new Integer(revoked + temprevoked), new Integer(reason));            	
            logSession.log(admin, bcdn.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_REVOKEDCERT, msg);
        } catch (Exception e) {
    		String msg = intres.getLocalizedMessage("store.errorrevokeallbyca", issuerdn);            	
            logSession.log(admin, bcdn.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_REVOKEDCERT, msg, e);
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, null);
            JDBCUtil.close(ps2);
        }
    }

    /**
     * Method that checks if a users all certificates have been revoked.
     *
     * @param admin    Administrator performing the operation
     * @param username the username to check for.
     * @return returns true if all certificates are revoked.
     * @ejb.interface-method
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
        		if (info != null) {
                    if (protect) {
                        // The verify method will log failed verifies itself
                        TableVerifyResult res = tableProtectSession.verify(info);
                        if (res.getResultCode() != TableVerifyResult.VERIFY_SUCCESS) {
                            // error("Verify failed, but we go on anyway.");
                        }
                    }
            		if (info.getStatus() != SecConst.CERT_REVOKED) {
            			returnval = false;
            		}        			
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
     * @ejb.interface-method
     */
    public boolean isRevoked(String issuerDN, BigInteger serno) {
        if (adapter.getLogger().isTraceEnabled()) {
            adapter.getLogger().trace(">isRevoked(), dn:" + issuerDN + ", serno=" + serno.toString(16));
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
                    adapter.error(msg);
                }
                Iterator<CertificateData> iter = coll.iterator();
                while (iter.hasNext()) {
                    CertificateData data = iter.next();
                    if (tableProtectSession != null) {
                        CertificateDataUtil.verifyProtection(data, tableProtectSession, adapter);
                    }
                    // if any of the certificates with this serno is revoked, return true
                    if (data.getStatus() == SecConst.CERT_REVOKED) {
                    	ret = true;
                    	break;
                    }
                }
            } else {
                // If there are no certificates with this serial number, return true (=revoked). Better safe than sorry!
            	ret = true;
            	if (adapter.getLogger().isTraceEnabled()) {
            		adapter.getLogger().trace("isRevoked() did not find certificate with dn "+dn+" and serno "+serno.toString(16));
            	}
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        if (adapter.getLogger().isTraceEnabled()) {
            adapter.getLogger().trace("<isRevoked() returned " + ret);
        }
        return ret;
    }

    /**
     * Get status fast.
     * 
     * @param issuerDN
     * @param serno
     * @return the status of the certificate
     * @ejb.interface-method
     */
    public CertificateStatus getStatus(String issuerDN, BigInteger serno) {
        return CertificateDataUtil.getStatus(issuerDN, serno, entityManager, tableProtectSession, adapter);
    }

    /**
     * Method that authenticates a certificate by checking validity and lookup if certificate is revoked.
     *
     * @param certificate the certificate to be authenticated.
     * @param requireAdminCertificateInDatabase if true the certificate has to exist in the database
     * @throws AuthenticationFailedException if authentication failed.
     * @ejb.interface-method
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
     * Checks the table protection information for a certificate data row
     *
     * @param admin    Administrator performing the operation
     * @param issuerDN the DN of the issuer.
     * @param serno    the serialnumber of the certificate that will be checked
     * @ejb.interface-method
     */
    public void verifyProtection(Admin admin, String issuerDN, BigInteger serno) {
        CertificateDataUtil.verifyProtection(admin, issuerDN, serno, entityManager, tableProtectSession, adapter);
    }

    /**
     * Method used to add a CertReqHistory to database
     * 
     * @param admin calling the methods
     * @param cert the certificate to store (Only X509Certificate used for now)
     * @param useradmindata the user information used when issuing the certificate.
     * @ejb.transaction type="Required"
     * @ejb.interface-method     
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
     * @ejb.transaction type="Required"    
     * @ejb.interface-method  
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
     * @ejb.interface-method
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
     * @ejb.interface-method
     */
    public List getCertReqHistory(Admin admin, String username){
    	ArrayList<CertReqHistory> retval = new ArrayList<CertReqHistory>();
    	Collection<CertReqHistoryData> result = CertReqHistoryData.findByUsername(entityManager, username);
    	Iterator<CertReqHistoryData> iter = result.iterator();
    	while(iter.hasNext()) {
    		retval.add(iter.next().getCertReqHistory());
    	}
    	return retval;
    }
    
    /**
     * A method designed to be called at startuptime to (possibly) upgrade certificate profiles.
     * This method will read all Certificate Profiles and as a side-effect upgrade them if the version if changed for upgrade.
     * Can have a side-effect of upgrading a profile, therefore the Required transaction setting.
     * 
     * @param admin administrator calling the method
     * 
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void initializeAndUpgradeProfiles(Admin admin) {
    	Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
    	Iterator<CertificateProfileData> iter = result.iterator();
    	while(iter.hasNext()) {
    		CertificateProfileData pdata = iter.next();
    		String name = pdata.getCertificateProfileName();
    		pdata.upgradeProfile();
    		float version = pdata.getCertificateProfile().getVersion();
    		log.debug("Loaded certificate profile: "+name+" with version "+version);
    	}
    }

    /**
     * Adds a certificate profile to the database.
     *
     * @param admin                  administrator performing the task
     * @param certificateprofilename readable name of new certificate profile
     * @param certificateprofile     the profile to be added
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void addCertificateProfile(Admin admin, String certificateprofilename,
                                      CertificateProfile certificateprofile) throws CertificateProfileExistsException {
        addCertificateProfile(admin, findFreeCertificateProfileId(), certificateprofilename, certificateprofile);
    }

    /**
     * Adds a certificate profile to the database.
     *
     * @param admin                  administrator performing the task
     * @param certificateprofileid   internal ID of new certificate profile, use only if you know it's right.
     * @param certificateprofilename readable name of new certificate profile
     * @param certificateprofile     the profile to be added
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void addCertificateProfile(Admin admin, int certificateprofileid, String certificateprofilename,
                                      CertificateProfile certificateprofile) throws CertificateProfileExistsException {
        if (isCertificateProfileNameFixed(certificateprofilename)) {
        	String msg = intres.getLocalizedMessage("store.errorcertprofilefixed", certificateprofilename);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
            throw new CertificateProfileExistsException(msg);
        }

        if (isFreeCertificateProfileId(certificateprofileid)) {
        	if (CertificateProfileData.findByProfileName(entityManager, certificateprofilename) != null) {
            	String msg = intres.getLocalizedMessage("store.errorcertprofileexists", certificateprofilename);            	
                throw new CertificateProfileExistsException(msg);
        	} else {
                try {
                	entityManager.persist(new CertificateProfileData(new Integer(certificateprofileid), certificateprofilename, certificateprofile));
                	String msg = intres.getLocalizedMessage("store.addedcertprofile", certificateprofilename);            	
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE, msg);
                } catch (Exception e) {
                	String msg = intres.getLocalizedMessage("store.errorcreatecertprofile", certificateprofilename);            	
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
                }
            }
        }
    }
    
    /**
     * Adds a certificateprofile  with the same content as the original certificateprofile,
     *
     * @param admin                          Administrator performing the operation
     * @param originalcertificateprofilename readable name of old certificate profile
     * @param newcertificateprofilename      readable name of new certificate profile
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void cloneCertificateProfile(Admin admin, String originalcertificateprofilename, String newcertificateprofilename, Collection authorizedCaIds) throws CertificateProfileExistsException {
        CertificateProfile certificateprofile = null;

        if (isCertificateProfileNameFixed(newcertificateprofilename)) {
        	String msg = intres.getLocalizedMessage("store.errorcertprofilefixed", newcertificateprofilename);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
            throw new CertificateProfileExistsException(msg);
        }

        try {
            certificateprofile = (CertificateProfile) getCertificateProfile(admin, originalcertificateprofilename).clone();

            boolean issuperadministrator = false;
            try {
                issuperadministrator = authorizationSession.isAuthorizedNoLog(admin, "/super_administrator");
            } catch (AuthorizationDeniedException ade) {
            }

            if (!issuperadministrator && certificateprofile.isApplicableToAnyCA()) {
                // Not superadministrator, do not use ANYCA;
                certificateprofile.setAvailableCAs(authorizedCaIds);
            }

            if (CertificateProfileData.findByProfileName(entityManager, newcertificateprofilename) != null) {
            	String msg = intres.getLocalizedMessage("store.erroraddprofilewithtempl", newcertificateprofilename, originalcertificateprofilename);            	
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
                throw new CertificateProfileExistsException();
            } else {
            	entityManager.persist(new CertificateProfileData(new Integer(findFreeCertificateProfileId()), newcertificateprofilename, certificateprofile));
            	String msg = intres.getLocalizedMessage("store.addedprofilewithtempl", newcertificateprofilename, originalcertificateprofilename);            	
            	logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE, msg);
            }
        } catch (CloneNotSupportedException f) {
        	throw new EJBException(f);	// If this happens it's a programming error. Throw an exception!
        }
    }

    /**
     * Removes a certificateprofile from the database, does not throw any errors if the profile does not exist, but it does log a message.
     *
     * @param admin Administrator performing the operation
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeCertificateProfile(Admin admin, String certificateprofilename) {
        try {
        	CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, certificateprofilename);
        	entityManager.remove(pdl);
        	String msg = intres.getLocalizedMessage("store.removedprofile", certificateprofilename);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE, msg);
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("store.errorremoveprofile", certificateprofilename);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
        }
    }

    /**
     * Renames a certificateprofile
     *
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void renameCertificateProfile(Admin admin, String oldcertificateprofilename, String newcertificateprofilename) throws CertificateProfileExistsException {
        if (isCertificateProfileNameFixed(newcertificateprofilename)) {
        	String msg = intres.getLocalizedMessage("store.errorcertprofilefixed", newcertificateprofilename);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
            throw new CertificateProfileExistsException(msg);
        }
        if (isCertificateProfileNameFixed(oldcertificateprofilename)) {
        	String msg = intres.getLocalizedMessage("store.errorcertprofilefixed", oldcertificateprofilename);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
            throw new CertificateProfileExistsException(msg);
        }
        if (CertificateProfileData.findByProfileName(entityManager, newcertificateprofilename) != null) {
        	String msg = intres.getLocalizedMessage("store.errorcertprofileexists", newcertificateprofilename);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
            throw new CertificateProfileExistsException();
        } else {
        	CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, oldcertificateprofilename);
        	if (pdl != null) {
                pdl.setCertificateProfileName(newcertificateprofilename);
            	String msg = intres.getLocalizedMessage("store.renamedprofile", oldcertificateprofilename, newcertificateprofilename);            	
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE, msg);
        	} else {
            	String msg = intres.getLocalizedMessage("store.errorrenameprofile", oldcertificateprofilename, newcertificateprofilename);            	
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
            }
        }
    }

    /**
     * Updates certificateprofile data
     *
     * @param admin Administrator performing the operation
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile) {
    	CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, certificateprofilename);
    	if (pdl != null) {
            pdl.setCertificateProfile(certificateprofile);
        	String msg = intres.getLocalizedMessage("store.editedprofile", certificateprofilename);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE, msg);
    	} else {
        	String msg = intres.getLocalizedMessage("store.erroreditprofile", certificateprofilename);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
        }
    }

    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     *
     * @param certprofiletype should be either CertificateDataBean.CERTTYPE_ENDENTITY, CertificateDataBean.CERTTYPE_SUBCA, CertificateDataBean.CERTTYPE_ROOTCA,
     *                        CertificateDataBean.CERTTYPE_HARDTOKEN (i.e EndEntity certificates and Hardtoken fixed profiles) or 0 for all.
     *                        Retrives certificate profile names sorted.
     * @param authorizedCaIds Collection<Integer> of authorized CA Ids for the specified Admin
     * @return Collection of id:s (Integer)
     * @ejb.interface-method
     */
    public Collection getAuthorizedCertificateProfileIds(Admin admin, int certprofiletype, Collection authorizedCaIds) {
        ArrayList<Integer> returnval = new ArrayList<Integer>();
        HashSet<Integer> authorizedcaids = new HashSet<Integer>(authorizedCaIds);

        // Add fixed certificate profiles.
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_ENDENTITY || certprofiletype == SecConst.CERTTYPE_HARDTOKEN){
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_ENDUSER));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_OCSPSIGNER));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_SERVER));
        }
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_SUBCA) {
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_SUBCA));
        }
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_ROOTCA) {
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_ROOTCA));
        }
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_HARDTOKEN) {
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENENC));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN));
        }
        Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
        Iterator<CertificateProfileData> i = result.iterator();
        while (i.hasNext()) {
        	CertificateProfileData next = i.next();
        	CertificateProfile profile = next.getCertificateProfile();
        	// Check if all profiles available CAs exists in authorizedcaids.
        	if (certprofiletype == 0 || certprofiletype == profile.getType()
        			|| (profile.getType() == SecConst.CERTTYPE_ENDENTITY &&
        					certprofiletype == SecConst.CERTTYPE_HARDTOKEN)) {
        		Iterator<Integer> availablecas = profile.getAvailableCAs().iterator();
        		boolean allexists = true;
        		while (availablecas.hasNext()) {
        			Integer nextcaid = availablecas.next();
        			if (nextcaid.intValue() == CertificateProfile.ANYCA) {
        				allexists = true;
        				break;
        			}
        			if (!authorizedcaids.contains(nextcaid)) {
        				allexists = false;
        				break;
        			}
        		}
        		if (allexists) {
        			returnval.add(next.getId());
        		}
        	}
        }
        return returnval;
    }

    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name (String).
     *
     * @param admin Administrator performing the operation
     * @ejb.interface-method
     */
    public HashMap getCertificateProfileIdToNameMap(Admin admin) {
        HashMap<Integer, String> returnval = new HashMap<Integer, String>();
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_ENDUSER),
                EndUserCertificateProfile.CERTIFICATEPROFILENAME);
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_SUBCA),
                CACertificateProfile.CERTIFICATEPROFILENAME);
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_ROOTCA),
                RootCACertificateProfile.CERTIFICATEPROFILENAME);

        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_OCSPSIGNER),
                OCSPSignerCertificateProfile.CERTIFICATEPROFILENAME);
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_SERVER),
                ServerCertificateProfile.CERTIFICATEPROFILENAME);

        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH),
                HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME);
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC),
                HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME);
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENENC),
                HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME);
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN),
                HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME);
        Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
        Iterator<CertificateProfileData> i = result.iterator();
        while (i.hasNext()) {
        	CertificateProfileData next = i.next();
        	returnval.put(next.getId(), next.getCertificateProfileName());
        }
        return returnval;
    }

    /**
     * Retrives a named certificate profile or null if none was found.
     *
     * @ejb.interface-method
     */
    public CertificateProfile getCertificateProfile(Admin admin, String certificateprofilename) {
        CertificateProfile returnval = null;

        if (certificateprofilename.equals(EndUserCertificateProfile.CERTIFICATEPROFILENAME)) {
            return new EndUserCertificateProfile();
        }
        if (certificateprofilename.equals(CACertificateProfile.CERTIFICATEPROFILENAME)) {
            return new CACertificateProfile();
        }
        if (certificateprofilename.equals(RootCACertificateProfile.CERTIFICATEPROFILENAME)) {
            return new RootCACertificateProfile();
        }
        if (certificateprofilename.equals(OCSPSignerCertificateProfile.CERTIFICATEPROFILENAME)) {
            return new OCSPSignerCertificateProfile();
        }
        if (certificateprofilename.equals(ServerCertificateProfile.CERTIFICATEPROFILENAME)) {
            return new ServerCertificateProfile();
        }
        if (certificateprofilename.equals(HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME)) {
            return new HardTokenAuthCertificateProfile();
        }
        if (certificateprofilename.equals(HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME)) {
            return new HardTokenAuthEncCertificateProfile();
        }
        if (certificateprofilename.equals(HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME)) {
            return new HardTokenEncCertificateProfile();
        }
        if (certificateprofilename.equals(HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME)) {
            return new HardTokenSignCertificateProfile();
        }

        CertificateProfileData cpd = CertificateProfileData.findByProfileName(entityManager, certificateprofilename);
        if (cpd != null) {
            returnval = cpd.getCertificateProfile();
        }
        return returnval;
    }

    /**
     * Finds a certificate profile by id.
     *
     * @param admin Administrator performing the operation
     * @return CertificateProfiles or null if it can not be found.
     * @ejb.interface-method
     */
    public CertificateProfile getCertificateProfile(Admin admin, int id) {
        CertificateProfile returnval = null;

        if (id < SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
            switch (id) {
                case SecConst.CERTPROFILE_FIXED_ENDUSER:
                    returnval = new EndUserCertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_SUBCA:
                    returnval = new CACertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_ROOTCA:
                    returnval = new RootCACertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_OCSPSIGNER:
                    returnval = new OCSPSignerCertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_SERVER:
                    returnval = new ServerCertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH:
                    returnval = new HardTokenAuthCertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC:
                    returnval = new HardTokenAuthEncCertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENENC:
                    returnval = new HardTokenEncCertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN:
                    returnval = new HardTokenSignCertificateProfile();
                    break;
                default:
                    returnval = new EndUserCertificateProfile();
            }
        } else {
            CertificateProfileData cpd = CertificateProfileData.findById(entityManager, Integer.valueOf(id));
            if (cpd != null) {
                returnval = cpd.getCertificateProfile();
            }
        }
        return returnval;
    }

    /**
     * Returns a certificate profile id, given it's certificate profile name
     *
     * @param admin Administrator performing the operation
     * @return the id or 0 if certificateprofile cannot be found.
     * @ejb.interface-method
     */
    public int getCertificateProfileId(Admin admin, String certificateprofilename) {
    	if (log.isTraceEnabled()) {
        	log.trace(">getCertificateProfileId: "+certificateprofilename);
    	}
        int returnval = 0;

        if (certificateprofilename.equals(EndUserCertificateProfile.CERTIFICATEPROFILENAME)) {
            return SecConst.CERTPROFILE_FIXED_ENDUSER;
        }
        if (certificateprofilename.equals(CACertificateProfile.CERTIFICATEPROFILENAME)) {
            return SecConst.CERTPROFILE_FIXED_SUBCA;
        }
        if (certificateprofilename.equals(RootCACertificateProfile.CERTIFICATEPROFILENAME)) {
            return SecConst.CERTPROFILE_FIXED_ROOTCA;
        }
        if (certificateprofilename.equals(OCSPSignerCertificateProfile.CERTIFICATEPROFILENAME)) {
            return SecConst.CERTPROFILE_FIXED_OCSPSIGNER;
        }
        if (certificateprofilename.equals(ServerCertificateProfile.CERTIFICATEPROFILENAME)) {
            return SecConst.CERTPROFILE_FIXED_SERVER;
        }
        if (certificateprofilename.equals(HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME)) {
            return SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH;
        }
        if (certificateprofilename.equals(HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME)) {
            return SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC;
        }
        if (certificateprofilename.equals(HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME)) {
            return SecConst.CERTPROFILE_FIXED_HARDTOKENENC;
        }
        if (certificateprofilename.equals(HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME)) {
            return SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN;
        }
        CertificateProfileData cpd = CertificateProfileData.findByProfileName(entityManager, certificateprofilename);
        if (cpd != null) {
            returnval = cpd.getId();
        } else {
        	log.debug("No certificate profile found with name: "+certificateprofilename);
        }
    	if (log.isTraceEnabled()) {
        	log.trace("<getCertificateProfileId: "+certificateprofilename);
    	}
        return returnval;
    }

    /**
     * Returns a certificateprofiles name given it's id.
     *
     * @param admin Administrator performing the operation
     * @return certificateprofilename or null if certificateprofile id doesn't exists.
     * @ejb.interface-method
     */
    public String getCertificateProfileName(Admin admin, int id) {
    	if (log.isTraceEnabled()) {
        	log.trace(">getCertificateProfileName: "+id);
    	}
        String returnval = null;
        // Is id a fixed profile
        if (id < SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
            switch (id) {
                case SecConst.CERTPROFILE_FIXED_ENDUSER:
                    returnval = EndUserCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_SUBCA:
                    returnval = CACertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_ROOTCA:
                    returnval = RootCACertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_OCSPSIGNER:
                    returnval = OCSPSignerCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_SERVER:
                    returnval = ServerCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH:
                    returnval = HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC:
                    returnval = HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENENC:
                    returnval = HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN:
                    returnval = HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                default:
                    returnval = EndUserCertificateProfile.CERTIFICATEPROFILENAME;
            }
        } else {
            CertificateProfileData cpd = CertificateProfileData.findById(entityManager, Integer.valueOf(id));
            if (cpd != null) {
                returnval = cpd.getCertificateProfileName();
            } else {
            	log.debug("No certificate profile found with id: "+id);
            }
        }
    	if (log.isTraceEnabled()) {
        	log.trace("<getCertificateProfileName: "+id);
    	}
        return returnval;
    }

    /**
     * Method to check if a CA exists in any of the certificate profiles. Used to avoid desyncronization of CA data.
     *
     * @param admin Administrator performing the operation
     * @param caid  the caid to search for.
     * @return true if ca exists in any of the certificate profiles.
     * @ejb.interface-method
     */
    public boolean existsCAInCertificateProfiles(Admin admin, int caid) {
        boolean exists = false;
        Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
        Iterator<CertificateProfileData> i = result.iterator();
        while (i.hasNext() && !exists) {
        	CertificateProfileData cd = i.next();
        	CertificateProfile certProfile = cd.getCertificateProfile(); 
        	if (certProfile.getType() == CertificateProfile.TYPE_ENDENTITY) {
        		Iterator<Integer> availablecas = certProfile.getAvailableCAs().iterator();
        		while (availablecas.hasNext()) {
        			if (availablecas.next().intValue() == caid ) {
        				exists = true;
        				log.debug("CA exists in certificate profile "+cd.getCertificateProfileName());
        				break;
        			}
        		}
        	}
        }
        return exists;
    }

    /**
     * Method to check if a Publisher exists in any of the certificate profiles. Used to avoid desyncronization of publisher data.
     *
     * @param publisherid the publisherid to search for.
     * @return true if publisher exists in any of the certificate profiles.
     * @ejb.interface-method
     */
    public boolean existsPublisherInCertificateProfiles(Admin admin, int publisherid) {
        boolean exists = false;
        Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
        Iterator<CertificateProfileData> i = result.iterator();
        while (i.hasNext() && !exists) {
        	Iterator<Integer> availablepublishers = i.next().getCertificateProfile().getPublisherList().iterator();
        	while (availablepublishers.hasNext()) {
        		if (availablepublishers.next().intValue() == publisherid) {
        			exists = true;
        			break;
        		}
        	}
        }
        return exists;
    }

    /**
     * @ejb.interface-method
     */
    public int findFreeCertificateProfileId() {
        Random random = new Random((new Date()).getTime());
        int id = random.nextInt();
        boolean foundfree = false;
        while (!foundfree) {
        	if (id > SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
        		if (CertificateProfileData.findById(entityManager, Integer.valueOf(id)) == null) {
        			foundfree = true;
        		}
        	} else {
        		id = random.nextInt();
        	}
        }
        return id;
    }

    // Private methods

    private boolean isCertificateProfileNameFixed(String certificateprofilename) {
        boolean returnval = false;
        if (certificateprofilename.equals(EndUserCertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (certificateprofilename.equals(CACertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (certificateprofilename.equals(RootCACertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (certificateprofilename.equals(OCSPSignerCertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (certificateprofilename.equals(ServerCertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        return returnval;
    }

    private boolean isFreeCertificateProfileId(int id) {
        boolean foundfree = false;
        if (id > SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
        	if (CertificateProfileData.findById(entityManager, Integer.valueOf(id)) == null) {
        		foundfree = true;
        	}
        }
        return foundfree;
    }

    private class MyAdapter implements CertificateDataUtil.Adapter {
        /*
         * @see org.ejbca.core.ejb.ca.store.CertificateDataUtil.Adapter#getLogger()
         */
        public Logger getLogger() {
            return log;
        }
        /*
         * @see org.ejbca.core.ejb.ca.store.CertificateDataUtil.Adapter#log(org.ejbca.core.model.log.Admin, int, int, java.util.Date, java.lang.String, java.security.cert.X509Certificate, int, java.lang.String)
         */
        public void log(Admin admin, int caid, int module, Date time, String username,
                        X509Certificate certificate, int event, String comment) {
            logSession.log(admin, caid, module, new java.util.Date(),
                                username, certificate, event, comment);
        }
        /*
         * @see org.ejbca.core.ejb.ca.store.CertificateDataUtil.Adapter#debug(java.lang.String)
         */
        public void debug(String s) {
            log.debug(s);
        }
        /*
         * @see org.ejbca.core.ejb.ca.store.CertificateDataUtil.Adapter#error(java.lang.String)
         */
        public void error(String s) {
            log.error(s);        	
        }
        /*
         * @see org.ejbca.core.ejb.ca.store.CertificateDataUtil.Adapter#error(java.lang.String)
         */
        public void error(String s, Exception e) {
            log.error(s, e);        	
        }
    }
}
