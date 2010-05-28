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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.protect.TableProtectSessionHome;
import org.ejbca.core.ejb.protect.TableProtectSessionRemote;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;

/**
 * Publisher writing certificates to an external Database, used by external OCSP responder.
 * 
 * @author lars
 * @version $Id$
 *
 */
public class ExternalOCSPPublisher extends BasePublisher implements ICustomPublisher {

    private static final Logger log = Logger.getLogger(ExternalOCSPPublisher.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    public static final float LATEST_VERSION = 1;
    
    public static final int TYPE_EXTOCSPPUBLISHER = 5;
    
    protected static final String DATASOURCE 				= "dataSource";
    protected static final String PROTECT 					= "protect";
    protected static final String STORECERT					= "storeCert";
    
    // Default values
    public static final String DEFAULT_DATASOURCE 			= "java:/OcspDS";
    public static final boolean DEFAULT_PROTECT 			= false;

    private final static String insertSQL = "INSERT INTO CertificateData (base64Cert,subjectDN,issuerDN,cAFingerprint,serialNumber,status,type,username,expireDate,revocationDate,revocationReason,tag,certificateProfileId,updateTime,fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    private final static String updateSQL = "UPDATE CertificateData SET base64Cert=?,subjectDN=?,issuerDN=?,cAFingerprint=?,serialNumber=?,status=?,type=?,username=?,expireDate=?,revocationDate=?,revocationReason=?,tag=?,certificateProfileId=?,updateTime=? WHERE fingerprint=?";
    /**
     * 
     */
    public ExternalOCSPPublisher() {
        super();
        data.put(TYPE, new Integer(TYPE_EXTOCSPPUBLISHER));
        setDataSource(DEFAULT_DATASOURCE);
        setProtect(DEFAULT_PROTECT);
    }

    /**
     *  Sets the data source property for the publisher.
     */
    public void setDataSource(String dataSource) {
		data.put(DATASOURCE, dataSource);
	}
    
    /**
     *  Sets the property protect for the publisher.
     */
    public void setProtect(boolean protect) {
		data.put(PROTECT, Boolean.valueOf(protect));
	}
    
    /**
     * @return The value of the property data source
     */
    public String getDataSource() {
    	return (String) data.get(DATASOURCE);
    }
    
    /**
     * @return The value of the property protect
     */
    public boolean getProtect() {
    	return ((Boolean) data.get(PROTECT)).booleanValue();
    }

    /**
     *  Sets the property protect for the publisher.
     */
    public void setStoreCert(boolean storecert) {
		data.put(STORECERT, Boolean.valueOf(storecert));
	}
    /**
     * @return The value of the property protect
     */
    public boolean getStoreCert() {
    	Object o = data.get(STORECERT);
    	boolean ret = true; // default value is true
    	if (o != null) {
    		ret = ((Boolean)o).booleanValue();
    	}
    	return ret;
    }

	/* (non-Javadoc)
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
     */
    public void init(Properties properties) {
        setDataSource(properties.getProperty(DATASOURCE));
        log.debug("dataSource='"+getDataSource()+"'.");
        String prot = properties.getProperty(PROTECT, "false"); // false is default for this
        setProtect(StringUtils.equalsIgnoreCase(prot, "true"));
        log.debug("protect='"+getProtect()+"'.");
        String storecert = properties.getProperty(STORECERT, "true"); // true is default for this
        setStoreCert(StringUtils.equalsIgnoreCase(storecert, "true"));
        log.debug("storeCert='"+getStoreCert()+"'.");
    }

    private class StoreCertPreparer implements JDBCUtil.Preparer {
        final Certificate incert;
        final String username;
        final String cafp;
        final int status;
        final int type;
        final long revocationDate;
        final int reason;
        final String tag;
        final int certificateProfileId;
        final long updateTime;
        StoreCertPreparer(Certificate ic,
                          String un, String cfp, int s, long d, int r, int t, String tag, int profid, long utime) {
            super();
            this.incert = ic;
            this.username = un;
            this.cafp = cfp;
            this.status = s;
            this.revocationDate = d;
            this.reason = r;
            this.type = t;
            this.tag = tag;
            this.certificateProfileId = profid;
            this.updateTime = utime;
        }
        public void prepare(PreparedStatement ps) throws Exception {
        	// We can select to publish the whole certificate, or not to. 
        	// There are good reasons not to publish the whole certificate. It is large, thus making it a bit of heavy insert and it may 
        	// contain sensitive information. 
        	// On the other hand some OCSP Extension plug-ins may not work without the certificate.
        	// A regular OCSP responder works fine without the certificate.
        	String cert = null;
        	if (getStoreCert()) {
        		cert = new String(Base64.encode(incert.getEncoded(), true));
        	}
            ps.setString(1, cert);
            ps.setString(2, CertTools.getSubjectDN(incert));
            ps.setString(3, CertTools.getIssuerDN(incert));
            ps.setString(4, cafp);
            ps.setString(5, ((X509Certificate)incert).getSerialNumber().toString());
            ps.setInt(6, status);
            ps.setInt(7, type);
            ps.setString(8, username);
            ps.setLong(9, ((X509Certificate)incert).getNotAfter().getTime());
            ps.setLong(10, revocationDate);
            ps.setInt(11, reason);
            ps.setString(12, tag);
            ps.setInt(13, certificateProfileId);
            ps.setLong(14, updateTime);
            ps.setString(15,CertTools.getFingerprintAsString(incert));
        }
        public String getInfoString() {
        	return "Store:, Username: "+username+", Issuer:"+CertTools.getIssuerDN(incert)+", Serno: "+CertTools.getSerialNumberAsString(incert)+", Subject: "+CertTools.getSubjectDN(incert);
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCertificate
     */
    public boolean storeCertificate(Admin admin, Certificate incert,
                                    String username, String password,
                                    String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
                                    ExtendedInformation extendedinformation)
    throws PublisherException {
    	boolean fail = true;
    	if (log.isDebugEnabled()) {
    		String fingerprint = CertTools.getFingerprintAsString(incert);
    		log.debug("Publishing certificate with fingerprint "+fingerprint+", status "+status+", type "+type+" to external OCSP");
    	}
    	StoreCertPreparer prep = new StoreCertPreparer(incert, username, cafp, status, revocationDate, revocationReason, type, tag, certificateProfileId, lastUpdate); 
    	try {
    		if (status == SecConst.CERT_REVOKED) {
        		// If this is a revocation we assume that the certificate already exists in the database. In that case we will try an update first and if that fails an insers.
        		JDBCUtil.execute(updateSQL, prep, getDataSource());
    		} else {
        		JDBCUtil.execute(insertSQL, prep, getDataSource());    			
    		}
    		fail = false;
    	} catch (Exception e) {
    		// If it is an SQL exception, we probably had a duplicate key, so we are actually trying to re-publish
    		if (e instanceof SQLException) {
    			if (log.isDebugEnabled()) {
    				String msg = intres.getLocalizedMessage("publisher.entryexists", e.getMessage());
    				log.debug(msg);
    			}
    			try {
    	    		if (status == SecConst.CERT_REVOKED) {
    	        		// If this is a revocation we tried an update below, if thart failed we have to do an insert here
    	        		JDBCUtil.execute(insertSQL, prep, getDataSource());    			
    	    		} else {
    	        		JDBCUtil.execute(updateSQL, prep, getDataSource());
    	    		}
            		fail = false;    				
    			} catch (Exception ue) {
    				String lmsg = intres.getLocalizedMessage("publisher.errorextocsppubl", prep.getInfoString());
    	            log.error(lmsg, ue);
    	            PublisherException pe = new PublisherException(lmsg);
    	            pe.initCause(ue);
    	            throw pe;				    				
    			}
			} else {
				String lmsg = intres.getLocalizedMessage("publisher.errorextocsppubl", prep.getInfoString());
	            log.error(lmsg, e);
	            PublisherException pe = new PublisherException(lmsg);
	            pe.initCause(e);
	            throw pe;				
			}
    	}
    	// If we managed to update the OCSP database, and protection is enabled, we have to update the protection database
    	if (!fail && getProtect()) {
    		X509Certificate cert = (X509Certificate)incert;
    		String fp = CertTools.getFingerprintAsString(cert);
    		String serno = cert.getSerialNumber().toString();
    		String issuer = CertTools.getIssuerDN(cert);
    		String subject = CertTools.getSubjectDN(cert);
    		long expire = cert.getNotAfter().getTime();
    		CertificateInfo entry = new CertificateInfo(fp, cafp, serno, issuer, subject, status, type, expire, revocationDate, revocationReason, username, tag, certificateProfileId, lastUpdate);
    		TableProtectSessionHome home = (TableProtectSessionHome)ServiceLocator.getInstance().getRemoteHome("TableProtectSession", TableProtectSessionHome.class);
            try {
				TableProtectSessionRemote remote = home.create();
				remote.protectExternal(entry, getDataSource());
			} catch (Exception e) {
				String msg = intres.getLocalizedMessage("protect.errorcreatesession");
				log.error(msg, e);
			} 

    	}
        return true;
    }

    /* Does nothing, this publisher only publishes Certificates.
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#storeCRL(se.anatom.ejbca.log.Admin, byte[], java.lang.String, int)
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp)
    throws PublisherException {
        return true;
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
        	JDBCUtil.execute("select 1 from CertificateData where fingerprint='XX'", new DoNothingPreparer(), getDataSource());
        } catch (Exception e) {
        	log.error("Connection test failed: ", e);
            final PublisherConnectionException pce = new PublisherConnectionException("Connection in init failed: "+e.getMessage());
            pce.initCause(e);
            throw pce;
        }
    }

	public Object clone() throws CloneNotSupportedException {
		ExternalOCSPPublisher clone = new ExternalOCSPPublisher();
		HashMap clonedata = (HashMap) clone.saveData();

		Iterator i = (data.keySet()).iterator();
		while(i.hasNext()){
			Object key = i.next();
			clonedata.put(key, data.get(key));
		}
		clone.loadData(clonedata);
		return clone;
	}

	public float getLatestVersion() {
		return LATEST_VERSION;
	}
}
