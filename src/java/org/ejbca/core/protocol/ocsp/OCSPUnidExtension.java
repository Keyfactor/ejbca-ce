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

package org.ejbca.core.protocol.ocsp;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Hashtable;

import javax.ejb.EJBException;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.ocsp.CertificateStatus;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;
import org.ejbca.util.JDBCUtil;

/** ASN.1 OCSP extension used to map a UNID to a Fnr, OID for this extension is 2.16.578.1.16.3.2
 * 
 * @author tomas
 * @version $Id: OCSPUnidExtension.java,v 1.6 2006-02-08 11:21:38 anatom Exp $
 *
 */
public class OCSPUnidExtension implements IOCSPExtension {

    static private final Logger m_log = Logger.getLogger(OCSPUnidExtension.class);

    private String dataSourceJndi;
    private Hashtable trustedCerts = new Hashtable();
    private X509Certificate cacert = null;
    private int errCode = OCSPUnidResponse.ERROR_NO_ERROR;
    
	/** Called after construction
	 * 
	 * @param config ServletConfig that can be used to read init-params from web-xml
	 */
	public void init(ServletConfig config) {
		// Datasource
		dataSourceJndi = config.getInitParameter("unidDataSource");
        if (StringUtils.isEmpty(dataSourceJndi)) {
            m_log.error("unidDataSource init-parameter must be set!");
            throw new IllegalArgumentException("unidDataSource init-parameter must be set!");
        }
        String trustDir = config.getInitParameter("unidTrustDir");
        if (StringUtils.isEmpty(trustDir)) {
            m_log.error("unidTrustDir init-parameter must be set!");
            throw new IllegalArgumentException("unidTrustDir init-parameter must be set!");
        }
        // read all files from trustDir, expect that they are PEM formatted certificates
        File dir = new File(trustDir);
        try {
            if (dir == null || dir.isDirectory() == false) {
                m_log.error(dir.getCanonicalPath()+ " is not a directory.");
                throw new IllegalArgumentException(dir.getCanonicalPath()+ " is not a directory.");                
            }
            File files[] = dir.listFiles();
            if (files == null || files.length == 0) {
                m_log.error("No files in trustDir directory: "+ dir.getCanonicalPath());                
            }
            for ( int i=0; i<files.length; i++ ) {
                final String fileName = files[i].getCanonicalPath();
                // Read the file, don't stop completely if one file has errors in it
                try {
                    byte[] bytes = FileTools.getBytesFromPEM(FileTools.readFiletoBuffer(fileName),
                            "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
                    X509Certificate cert = CertTools.getCertfromByteArray(bytes);
                    String key = CertTools.getIssuerDN(cert)+";"+cert.getSerialNumber().toString(16);
                    trustedCerts.put(key,cert);
                } catch (CertificateException e) {
                    m_log.error("Error reading "+fileName+" from trustDir: ", e);
                } catch (IOException e) {
                    m_log.error("Error reading "+fileName+" from trustDir: ", e);
                }
            }
        } catch (IOException e) {
            m_log.error("Error reading files from trustDir: ", e);
            throw new IllegalArgumentException("Error reading files from trustDir: "+e.getMessage());
        }
        String cacertfile = config.getInitParameter("unidCACert");
        if (StringUtils.isEmpty(cacertfile)) {
            m_log.error("unidCACert init-parameter must be set!");
            throw new IllegalArgumentException("unidCACert init-parameter must be set!");
        }
        try {
            byte[] bytes = FileTools.getBytesFromPEM(FileTools
                    .readFiletoBuffer(cacertfile),
                    "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
            cacert = CertTools.getCertfromByteArray(bytes);
        } catch (Exception e) {
            m_log.error("Error reading file from cacertfile: ", e);
            throw new IllegalArgumentException("Error reading files from cacertfile: "+e.getMessage());
        }

	}
	
	/** Called by OCSP responder when the configured extension is found in the request.
	 * 
	 * @param request HttpServletRequest that can be used to find out information about caller, TLS certificate etc.
	 * @param cert X509Certificate the caller asked for in the OCSP request
     * @param status CertificateStatus the status the certificate has according to the OCSP responder, null means the cert is good
	 * @return X509Extension that will be added to responseExtensions by OCSP responder, or null if an error occurs
	 */
	public Hashtable process(HttpServletRequest request, X509Certificate cert, CertificateStatus status) {
        m_log.debug(">process()");
        // Check authorization first
        if (!checkAuthorization(request)) {
        	errCode = OCSPUnidResponse.ERROR_UNAUTHORIZED;
        	return null;
        }
        // If the certificate is revoked, we must not return an FNR
        if (status != null) {
            errCode = OCSPUnidResponse.ERROR_CERT_REVOKED;
            return null;
        }
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet result = null;
    	String fnr = null;
        String sn = null;
        try {
        	// The Unis is in the DN component serialNumber
        	sn = CertTools.getPartFromDN(cert.getSubjectDN().getName(), "SN");
        	if (sn != null) {
        		m_log.debug("Found serialNumber: "+sn);
        		try {
        			con = ServiceLocator.getInstance().getDataSource(dataSourceJndi).getConnection();
        		} catch (SQLException e) {
        			m_log.error("Got SQL exception when looking up databasource for Unid-Fnr mapping: ", e);
        			errCode = OCSPUnidResponse.ERROR_SERVICE_UNAVAILABLE;
        			return null;
        		}
                ps = con.prepareStatement("select fnr from UnidFnrMapping where unid=?");
                ps.setString(1, sn);
                result = ps.executeQuery();
                if (result.next()) {
                    fnr = result.getString(1);
                }
        	} else {
        		m_log.error("Did not find a serialNumber in DN: "+cert.getSubjectDN().getName());
        		errCode = OCSPUnidResponse.ERROR_NO_SERIAL_IN_DN;
        		return null;
        	}
            m_log.debug("<process()");
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
        
        // Construct the response extentsion if we found a mapping
        if (fnr == null) {
            m_log.error("No Fnr mapping exists for UNID "+sn);
        	errCode = OCSPUnidResponse.ERROR_NO_FNR_MAPPING;
        	return null;
        	
        }
        FnrFromUnidExtension ext = new FnrFromUnidExtension(fnr);
        Hashtable ret = new Hashtable();
        ret.put(FnrFromUnidExtension.FnrFromUnidOid, new X509Extension(false, new DEROctetString(ext)));
		return ret;
	}
	
	/** Returns the last error that occured during process(), when process returns null
	 * 
	 * @return error code as defined by implementing class
	 */
	public int getLastErrorCode() {
		return errCode;
	}
	
	// 
	// Private methods
	//
	boolean checkAuthorization(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        if (certs == null) {
            m_log.error("Got request without client authentication from (ip;fqdn): "+request.getRemoteAddr()+"; "+request.getRemoteHost());
            return false;
        }
        // The entitys certificate is nr 0
        X509Certificate cert = certs[0];
        if (cert == null) {
            m_log.error("Got request without client authentication from (ip;fqdn): "+request.getRemoteAddr()+"; "+request.getRemoteHost());
            return false;
        }
        // Check if the certificate is authorized to access the Fnr
        String key = CertTools.getIssuerDN(cert)+";"+cert.getSerialNumber().toString(16);
        Object found = trustedCerts.get(key);
        if (found != null) {
            // If we found in the hashmap the same key with issuer and serialnumber, we know we got it. 
            // Just verify it as well to be damn sure
            try {
                cert.verify(cacert.getPublicKey());
            } catch (Exception e) {
                m_log.error("Exception when trying to verify client certificate: ", e);
                return false;
            }
            // If verify was succesful we know if was good!
            return true;
        }
        m_log.error("Got request with untrusted client cert from (ip;fqdn): "+request.getRemoteAddr()+"; "+request.getRemoteHost());
		return false;
	}
}
