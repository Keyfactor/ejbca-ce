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

package org.ejbca.core.model.ca.publisher;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.protect.TableProtectSessionHome;
import org.ejbca.core.ejb.protect.TableProtectSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;

/**
 * @author lars
 * @version $Id: ExternalOCSPPublisher.java,v 1.9 2006-08-06 12:37:00 anatom Exp $
 *
 */
public class ExternalOCSPPublisher implements ICustomPublisher {

    private static Logger log = Logger.getLogger(ExternalOCSPPublisher.class);
    private String dataSource;
    private boolean protect = false;

    /**
     * 
     */
    public ExternalOCSPPublisher() {
        super();
    }

    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#init(java.util.Properties)
     */
    public void init(Properties properties) {
        dataSource = properties.getProperty("dataSource");
        String prot = properties.getProperty("protect");
        if (StringUtils.equalsIgnoreCase(prot, "true")) {
        	protect = true;
        }
        log.debug("dataSource='"+dataSource+"'.");
    }

    protected class StoreCertPreparer implements JDBCUtil.Preparer {
        final Certificate incert;
        final String username;
        final String cafp;
        final int status;
        final int type;
        final long revocationDate;
        final int reason;
        StoreCertPreparer(Certificate ic,
                          String un, String cf, int s, long d, int r, int t) {
            super();
            incert = ic;
            username = un;
            cafp = cf;
            status = s;
            type = t;
            revocationDate = d;
            reason = r;
        }
        public void prepare(PreparedStatement ps) throws Exception {
            ps.setString(1, new String(Base64.encode(incert.getEncoded(), true)));
            ps.setString(2, CertTools.getSubjectDN((X509Certificate)incert));
            ps.setString(3, CertTools.getIssuerDN((X509Certificate)incert));
            ps.setString(4, cafp);
            ps.setString(5, ((X509Certificate)incert).getSerialNumber().toString());
            ps.setInt(6, status);
            ps.setInt(7, type);
            ps.setString(8, username);
            ps.setLong(9, ((X509Certificate)incert).getNotAfter().getTime());
            ps.setLong(10, revocationDate);
            ps.setInt(11, reason);
            ps.setString(12,CertTools.getFingerprintAsString((X509Certificate)incert));
        }
        public String getInfoString() {
        	return "Store:, Username: "+username+", Issuer:"+CertTools.getIssuerDN((X509Certificate)incert)+", Serno: "+((X509Certificate)incert).getSerialNumber().toString()+", Subject: "+CertTools.getSubjectDN((X509Certificate)incert);
        }
    }

    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#storeCertificate(se.anatom.ejbca.log.Admin, java.security.cert.Certificate, java.lang.String, java.lang.String, java.lang.String, int, int, se.anatom.ejbca.ra.ExtendedInformation)
     */
    public boolean storeCertificate(Admin admin, Certificate incert,
                                    String username, String password,
                                    String cafp, int status, int type, long revocationDate, int revocationReason,
                                    ExtendedInformation extendedinformation)
    throws PublisherException {
    	boolean fail = true;
    	if (log.isDebugEnabled()) {
    		String fingerprint = CertTools.getFingerprintAsString((X509Certificate)incert);
    		log.debug("Publishing certificate with fingerprint "+fingerprint+", status "+status+", type "+type+" to external OCSP");
    	}
    	StoreCertPreparer prep = new StoreCertPreparer(incert, username, cafp, status, revocationDate, revocationReason, type); 
    	try {
    		JDBCUtil.execute( "INSERT INTO CertificateData (base64Cert,subjectDN,issuerDN,cAFingerprint,serialNumber,status,type,username,expireDate,revocationDate,revocationReason,fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);",
    				prep, dataSource);
    		fail = false;
    	} catch (Exception e) {
    		// If it is an SQL exception, we probably had a duplicate key, so we are actually trying to re-publish
    		if (e instanceof SQLException) {
    			log.info("Duplicate entry, updating instead.");
    			//JDBCPreparer uprep = new UpdatePreparer(incert, status, revocationDate, revocationReason);
    			StoreCertPreparer uprep = new StoreCertPreparer(incert, username, cafp, status, revocationDate, revocationReason, type); 
    			try {
        			JDBCUtil.execute( "UPDATE CertificateData SET base64Cert=?,subjectDN=?,issuerDN=?,cAFingerprint=?,serialNumber=?,status=?,type=?,username=?,expireDate=?,revocationDate=?,revocationReason=? WHERE fingerprint=?;",
            				uprep, dataSource );
            		fail = false;    				
    			} catch (Exception ue) {
    	            log.error("EXTERNAL OCSP ERROR, publishing is not working for - "+uprep.getInfoString()+": ", ue);
    	            PublisherException pe = new PublisherException("EXTERNAL OCSP ERROR, publishing is not working");
    	            pe.initCause(ue);
    	            throw pe;				    				
    			}
			} else {
	            log.error("EXTERNAL OCSP ERROR, publishing is not working for - "+prep.getInfoString()+": ", e);
	            PublisherException pe = new PublisherException("EXTERNAL OCSP ERROR, publishing is not working");
	            pe.initCause(e);
	            throw pe;				
			}
    	}
    	// If we managed to update the OCSP database, and protection is enabled, we have to update the protection database
    	if (!fail && protect) {
    		X509Certificate cert = (X509Certificate)incert;
    		String fp = CertTools.getFingerprintAsString(cert);
    		String serno = cert.getSerialNumber().toString();
    		String issuer = CertTools.getIssuerDN(cert);
    		String subject = CertTools.getSubjectDN(cert);
    		long expire = cert.getNotAfter().getTime();
    		CertificateInfo entry = new CertificateInfo(fp, cafp, serno, issuer, subject, status, type, expire, revocationDate, revocationReason);
    		TableProtectSessionHome home = (TableProtectSessionHome)ServiceLocator.getInstance().getRemoteHome("TableProtectSession", TableProtectSessionHome.class);
            try {
				TableProtectSessionRemote remote = home.create();
				remote.protectExternal(admin, entry, dataSource);
			} catch (Exception e) {
				log.error("PROTECT ERROR: Can not create TableProtectSession: ", e);
			} 

    	}
        return true;
    }

    /* Does nothing, this publisher only publishes Certificates.
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#storeCRL(se.anatom.ejbca.log.Admin, byte[], java.lang.String, int)
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number)
    throws PublisherException {
        return true;
    }

    protected class UpdatePreparer implements JDBCUtil.Preparer {
        final Certificate cert;
        final int reason;
        final int status;
        final long date;
        UpdatePreparer(Certificate c, int s, long d, int r) {
            cert = c;
            reason = r;
            date = d;
            status = s;
        }
        public void prepare(PreparedStatement ps) throws Exception {
            ps.setInt(1, status);
            ps.setLong(2, date);
            ps.setInt(3, reason);
            ps.setString(4, CertTools.getFingerprintAsString((X509Certificate)cert));
        }
        public String getInfoString() {
        	return "Revoke:, Issuer:"+CertTools.getIssuerDN((X509Certificate)cert)+", Serno: "+((X509Certificate)cert).getSerialNumber().toString()+", Subject: "+CertTools.getSubjectDN((X509Certificate)cert);
        	
        }
    }
    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#revokeCertificate(se.anatom.ejbca.log.Admin, java.security.cert.Certificate, int)
     */
    public void revokeCertificate(Admin admin, Certificate incert, int reason) throws PublisherException {
    	if (log.isDebugEnabled()) {
    		String fingerprint = CertTools.getFingerprintAsString((X509Certificate)incert);
    		log.debug("Revoking certificate with fingerprint "+fingerprint+", reason "+reason+" in external OCSP");
    	}
    	boolean fail = true;
    	long now = System.currentTimeMillis();
    	UpdatePreparer prep = new UpdatePreparer(incert, 40, now, reason);
    	try {
			JDBCUtil.execute( "UPDATE CertificateData SET status=?, revocationDate=?, revocationReason=? WHERE fingerprint=?;",
			         prep, dataSource);
			fail = false;
		} catch (Exception e) {
            log.error("EXTERNAL OCSP ERROR, publishing is not working for - "+prep.getInfoString()+": ", e);
            PublisherException pe = new PublisherException("EXTERNAL OCSP ERROR, publishing is not working");
            pe.initCause(e);
            throw pe;
		}
    	// If we managed to update the OCSP database, and protection is enabled, we have to update the protection database
    	if (!fail && protect) {
    		X509Certificate cert = (X509Certificate)incert;
    		String fp = CertTools.getFingerprintAsString(cert);
    		String serno = cert.getSerialNumber().toString();
    		String issuer = CertTools.getIssuerDN(cert);
    		String subject = CertTools.getSubjectDN(cert);
    		long expire = cert.getNotAfter().getTime();
    		// Cafp and type we don't have access to here, we don't use them so enter dummy values
    		CertificateInfo entry = new CertificateInfo(fp, null, serno, issuer, subject, 40, SecConst.USER_ENDUSER, expire, now, reason);
    		TableProtectSessionHome home = (TableProtectSessionHome)ServiceLocator.getInstance().getRemoteHome("TableProtectSession", TableProtectSessionHome.class);
            try {
				TableProtectSessionRemote remote = home.create();
				remote.protectExternal(admin, entry, dataSource);
			} catch (Exception e) {
				log.error("PROTECT ERROR: Can not create TableProtectSession: ", e);
			} 
    	}
    }

    protected class DoNothingPreparer implements JDBCUtil.Preparer {
        public void prepare(PreparedStatement ps) {
        }
        public String getInfoString() {
        	return null;
        }
    }
    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#testConnection(se.anatom.ejbca.log.Admin)
     */
    public void testConnection(Admin admin) throws PublisherConnectionException {
        try {
        	JDBCUtil.execute("UNLOCK TABLES;", new DoNothingPreparer(), dataSource);
        } catch (Exception e) {
            final PublisherConnectionException pce = new PublisherConnectionException("Connection in init failed: "+e.getMessage());
            pce.initCause(e);
            throw pce;
        }
    }
}
