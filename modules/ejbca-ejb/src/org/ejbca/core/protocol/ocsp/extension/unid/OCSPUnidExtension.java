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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
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
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.unidfnr.ejb.UnidfnrSessionLocal;

/** ASN.1 OCSP extension used to map a UNID to a Fnr, OID for this extension is 2.16.578.1.16.3.2
 * 
 * @version $Id$
 *
 */
public class OCSPUnidExtension implements OCSPExtension {

    public static final String OCSP_UNID_OID = "2.16.578.1.16.3.2";
    
	private static final Logger log = Logger.getLogger(OCSPUnidExtension.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    private final UnidfnrSessionLocal unidfnrSession = new EjbLocalHelper().getUnidfnrSession();
    
    private String dataSourceJndi;
    private Set<BigInteger> trustedCerts = new HashSet<BigInteger>();
    private Certificate cacert = null;
    private int errCode = UnidFnrOCSPExtensionCode.ERROR_NO_ERROR.getValue();
    
	@Override
	public void init() {
		// DataSource
		dataSourceJndi = OcspConfiguration.getUnidDataSource();
        if (StringUtils.isEmpty(dataSourceJndi)) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornoinitparam", "unidDataSource");
            log.error(errMsg);
            throw new IllegalArgumentException(errMsg);
        }
        String trustDir = OcspConfiguration.getUnidTrustDir();
        if (StringUtils.isEmpty(trustDir)) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornoinitparam", "unidTrustDir");
            log.error(errMsg);
            throw new IllegalArgumentException(errMsg);
        }
        // read all files from trustDir, expect that they are PEM formatted certificates
        CryptoProviderTools.installBCProviderIfNotAvailable();
        File dir = new File(trustDir);
        try {
            if (dir == null || dir.isDirectory() == false) {
                log.error(dir.getCanonicalPath()+ " is not a directory.");
                throw new IllegalArgumentException(dir.getCanonicalPath()+ " is not a directory.");                
            }
            List<File> files = Arrays.asList(dir.listFiles());
            if (files == null || files.isEmpty()) {
        		String errMsg = intres.getLocalizedMessage("ocsp.errornotrustfiles", dir.getCanonicalPath());
                log.error(errMsg);                
            }
            for (final File file : files) {
                final String fileName = file.getCanonicalPath();
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
                    log.error(errMsg, e);
                } catch (IOException e) {
            		String errMsg = intres.getLocalizedMessage("ocsp.errorreadingfile", fileName, "trustDir", e.getMessage());
                    log.error(errMsg, e);
                }
            }
        } catch (IOException e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorreadingtrustfiles", e.getMessage());
            log.error(errMsg, e);
            throw new IllegalArgumentException(errMsg);
        }
        String cacertfile = OcspConfiguration.getUnidCaCert();
        
        if (StringUtils.isEmpty(cacertfile)) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornoinitparam", "unidCACert");
            log.error(errMsg);
            throw new IllegalArgumentException(errMsg);
        }
        try {
            byte[] bytes = FileTools.getBytesFromPEM(FileTools
                    .readFiletoBuffer(cacertfile),
                    CertTools.BEGIN_CERTIFICATE, CertTools.END_CERTIFICATE);
            cacert = CertTools.getCertfromByteArray(bytes, Certificate.class);
        } catch (Exception e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorreadingfile", "file", "cacertfile", e.getMessage());
            log.error(errMsg, e);
            throw new IllegalArgumentException(errMsg);
        }
	}
	
	@Override
	public Map<ASN1ObjectIdentifier, Extension> process(X509Certificate[] requestCertificates, String remoteAddress, String remoteHost,
            X509Certificate cert, CertificateStatus status) {
        if (log.isTraceEnabled()) {
            log.trace(">process()");            
        }
        
        // Check authorization first
        if (!checkAuthorization(requestCertificates, remoteAddress, remoteHost)) {
        	errCode = UnidFnrOCSPExtensionCode.ERROR_UNAUTHORIZED.getValue();
        	return null;
        }
        // If the certificate is revoked, we must not return an FNR
        if (status != null) {
            errCode = UnidFnrOCSPExtensionCode.ERROR_CERT_REVOKED.getValue();
            return null;
        }

        String serialNumber = null;
        String fnr = null;
        try {
        	// The Unis is in the DN component serialNumber
        	serialNumber = CertTools.getPartFromDN(cert.getSubjectDN().getName(), "SN");
        	if (serialNumber != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Found serialNumber: " + serialNumber);                    
                }
				String iMsg = intres.getLocalizedMessage("ocsp.receivedunidreq", remoteAddress, remoteHost, serialNumber);
                log.info(iMsg);
        		fnr = unidfnrSession.fetchUnidFnrData(serialNumber);

        	} else {
				String errMsg = intres.getLocalizedMessage("ocsp.errorunidnosnindn", cert.getSubjectDN().getName());
        		log.error(errMsg);
        		errCode = UnidFnrOCSPExtensionCode.ERROR_NO_SERIAL_IN_DN.getValue();
        		return null;
        	}
            log.trace("<process()");
        } catch (Exception e) {
            throw new EJBException(e);
        } 
        
        // Construct the response extension if we found a mapping
        if (fnr == null) {
			String errMsg = intres.getLocalizedMessage("ocsp.errorunidnosnmapping", serialNumber);
            log.error(errMsg);
        	errCode = UnidFnrOCSPExtensionCode.ERROR_NO_FNR_MAPPING.getValue();
        	return null;
        }
		String errMsg = intres.getLocalizedMessage("ocsp.returnedunidresponse", remoteAddress, remoteHost, fnr, serialNumber);
        log.info(errMsg);
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
            log.error(errMsg);
            return false;
        }
        // The certificate of the entity is nr 0
        X509Certificate cert = certificates[0];
        if (cert == null) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornoclientauth", remoteAddress, remoteHost);
            log.error(errMsg);
            return false;
        }
        
        // Check if the certificate is authorized to access the Fnr
        if (this.trustedCerts.contains(cert.getSerialNumber())) {
            // If we found in the hashmap the same key with issuer and serialnumber, we know we got it. 
            // Just verify it as well to be damn sure
            try {
                cert.verify(this.cacert.getPublicKey());
            } catch (Exception e) {
        		String errMsg = intres.getLocalizedMessage("ocsp.errorverifycert");
                log.error(errMsg, e);
                return false;
            }
            // If verify was successful we know if was good!
            return true;
        }
        
		String errMsg = intres.getLocalizedMessage("ocsp.erroruntrustedclientauth", remoteAddress, remoteHost);
        log.error(errMsg);
		return false;
	}
}
