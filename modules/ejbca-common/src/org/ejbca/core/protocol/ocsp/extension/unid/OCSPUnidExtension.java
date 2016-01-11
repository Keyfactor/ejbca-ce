/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.ocsp.extension.unid;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJBException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.cesecore.certificates.ocsp.extension.OCSPExtension;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.util.JDBCUtil;

/** ASN.1 OCSP extension used to map a UNID to a Fnr, OID for this extension is 2.16.578.1.16.3.2
 * 
 * @version $Id$
 *
 */
public class OCSPUnidExtension implements OCSPExtension {

	private static final Logger m_log = Logger.getLogger(OCSPUnidExtension.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

	/** Constants capturing the possible error returned by the Unid-Fnr OCSP Extension 
	 * 
	 */
	public static final int ERROR_NO_ERROR = 0;
	public static final int ERROR_UNKNOWN = 1;
	public static final int ERROR_UNAUTHORIZED = 2;
	public static final int ERROR_NO_FNR_MAPPING = 3;
	public static final int ERROR_NO_SERIAL_IN_DN = 4;
	public static final int ERROR_SERVICE_UNAVAILABLE = 5;
    public static final int ERROR_CERT_REVOKED = 6;
    
    private String dataSourceJndi;
    private Set<BigInteger> trustedCerts = new HashSet<BigInteger>();
    private Certificate cacert = null;
    private int errCode = OCSPUnidExtension.ERROR_NO_ERROR;
    
	@Override
	public void init() {
		// DataSource
		dataSourceJndi = OcspConfiguration.getUnidDataSource();
        if (StringUtils.isEmpty(dataSourceJndi)) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornoinitparam", "unidDataSource");
            m_log.error(errMsg);
            throw new IllegalArgumentException(errMsg);
        }
        String trustDir = OcspConfiguration.getUnidTrustDir();
        if (StringUtils.isEmpty(trustDir)) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornoinitparam", "unidTrustDir");
            m_log.error(errMsg);
            throw new IllegalArgumentException(errMsg);
        }
        // read all files from trustDir, expect that they are PEM formatted certificates
        CryptoProviderTools.installBCProviderIfNotAvailable();
        File dir = new File(trustDir);
        try {
            if (dir == null || dir.isDirectory() == false) {
                m_log.error(dir.getCanonicalPath()+ " is not a directory.");
                throw new IllegalArgumentException(dir.getCanonicalPath()+ " is not a directory.");                
            }
            File files[] = dir.listFiles();
            if (files == null || files.length == 0) {
        		String errMsg = intres.getLocalizedMessage("ocsp.errornotrustfiles", dir.getCanonicalPath());
                m_log.error(errMsg);                
            }
            for ( int i=0; i<files.length; i++ ) {
                final String fileName = files[i].getCanonicalPath();
                // Read the file, don't stop completely if one file has errors in it
                try {
                    final byte bFromFile[] = FileTools.readFiletoBuffer(fileName);
                    byte[] bytes;
                    try {
                        bytes = FileTools.getBytesFromPEM(bFromFile, CertTools.BEGIN_CERTIFICATE, CertTools.END_CERTIFICATE);
                    } catch( Exception t ) {
                        bytes = bFromFile; // assume binary data (.der)
                    }
                    final X509Certificate  cert = CertTools.getCertfromByteArray(bytes, X509Certificate.class);
                    this.trustedCerts.add(cert.getSerialNumber());
                } catch (CertificateException e) {
            		String errMsg = intres.getLocalizedMessage("ocsp.errorreadingfile", fileName, "trustDir", e.getMessage());
                    m_log.error(errMsg, e);
                } catch (IOException e) {
            		String errMsg = intres.getLocalizedMessage("ocsp.errorreadingfile", fileName, "trustDir", e.getMessage());
                    m_log.error(errMsg, e);
                }
            }
        } catch (IOException e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorreadingtrustfiles", e.getMessage());
            m_log.error(errMsg, e);
            throw new IllegalArgumentException(errMsg);
        }
        String cacertfile = OcspConfiguration.getUnidCaCert();
        if (StringUtils.isEmpty(cacertfile)) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornoinitparam", "unidCACert");
            m_log.error(errMsg);
            throw new IllegalArgumentException(errMsg);
        }
        try {
            byte[] bytes = FileTools.getBytesFromPEM(FileTools
                    .readFiletoBuffer(cacertfile),
                    CertTools.BEGIN_CERTIFICATE, CertTools.END_CERTIFICATE);
            cacert = CertTools.getCertfromByteArray(bytes, Certificate.class);
        } catch (Exception e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorreadingfile", "file", "cacertfile", e.getMessage());
            m_log.error(errMsg, e);
            throw new IllegalArgumentException(errMsg);
        }

	}
	
	@Override
	public Map<ASN1ObjectIdentifier, Extension> process(X509Certificate[] requestCertificates, String remoteAddress, String remoteHost,
            X509Certificate cert, CertificateStatus status) {
        if (m_log.isTraceEnabled()) {
            m_log.trace(">process()");            
        }
        // Check authorization first
        if (!checkAuthorization(requestCertificates, remoteAddress, remoteHost)) {
        	errCode = OCSPUnidExtension.ERROR_UNAUTHORIZED;
        	return null;
        }
        // If the certificate is revoked, we must not return an FNR
        if (status != null) {
            errCode = OCSPUnidExtension.ERROR_CERT_REVOKED;
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
                if (m_log.isDebugEnabled()) {
                    m_log.debug("Found serialNumber: "+sn);                    
                }
				String iMsg = intres.getLocalizedMessage("ocsp.receivedunidreq", remoteAddress, remoteHost, sn);
                m_log.info(iMsg);
        		try {
        			con = ServiceLocator.getInstance().getDataSource(dataSourceJndi).getConnection();
        		} catch (SQLException e) {
    				String errMsg = intres.getLocalizedMessage("ocsp.errordatabaseunid");
        			m_log.error(errMsg, e);
        			errCode = OCSPUnidExtension.ERROR_SERVICE_UNAVAILABLE;
        			return null;
        		}
                ps = con.prepareStatement("select fnr from UnidFnrMapping where unid=?");
                ps.setString(1, sn);
                result = ps.executeQuery();
                if (result.next()) {
                    fnr = result.getString(1);
                }
        	} else {
				String errMsg = intres.getLocalizedMessage("ocsp.errorunidnosnindn", cert.getSubjectDN().getName());
        		m_log.error(errMsg);
        		errCode = OCSPUnidExtension.ERROR_NO_SERIAL_IN_DN;
        		return null;
        	}
            m_log.trace("<process()");
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
        
        // Construct the response extentsion if we found a mapping
        if (fnr == null) {
			String errMsg = intres.getLocalizedMessage("ocsp.errorunidnosnmapping", sn);
            m_log.error(errMsg);
        	errCode = OCSPUnidExtension.ERROR_NO_FNR_MAPPING;
        	return null;
        	
        }
		String errMsg = intres.getLocalizedMessage("ocsp.returnedunidresponse", remoteAddress, remoteHost, fnr, sn);
        m_log.info(errMsg);
        FnrFromUnidExtension ext = new FnrFromUnidExtension(fnr);
        HashMap<ASN1ObjectIdentifier, Extension> ret = new HashMap<ASN1ObjectIdentifier, Extension>();
        try {
            ret.put(FnrFromUnidExtension.FnrFromUnidOid, new Extension(FnrFromUnidExtension.FnrFromUnidOid, false, new DEROctetString(ext)));
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException caught.", e);
        }
		return ret;
	}
	
	/** Returns the last error that occured during process(), when process returns null
	 * 
	 * @return error code as defined by implementing class
	 */
	public int getLastErrorCode() {
		return errCode;
	}
	
	private boolean checkAuthorization(X509Certificate[] certificates, String remoteAddress, String remoteHost) {
        
        if (certificates == null) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornoclientauth", remoteAddress, remoteHost);
            m_log.error(errMsg);
            return false;
        }
        // The certificate of the entity is nr 0
        X509Certificate cert = certificates[0];
        if (cert == null) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornoclientauth", remoteAddress, remoteHost);
            m_log.error(errMsg);
            return false;
        }
        // Check if the certificate is authorised to access the Fnr
        if ( this.trustedCerts.contains(cert.getSerialNumber()) ) {
            // If we found in the hashmap the same key with issuer and serialnumber, we know we got it. 
            // Just verify it as well to be damn sure
            try {
                cert.verify(this.cacert.getPublicKey());
            } catch (Exception e) {
        		String errMsg = intres.getLocalizedMessage("ocsp.errorverifycert");
                m_log.error(errMsg, e);
                return false;
            }
            // If verify was successful we know if was good!
            return true;
        }
		String errMsg = intres.getLocalizedMessage("ocsp.erroruntrustedclientauth", remoteAddress, remoteHost);
        m_log.error(errMsg);
		return false;
	}
}
