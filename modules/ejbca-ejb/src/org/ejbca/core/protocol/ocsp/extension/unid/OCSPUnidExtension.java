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

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ocsp.extension.OCSPExtension;
import org.cesecore.certificates.ocsp.extension.OCSPExtensionType;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.ejbca.core.ejb.unidfnr.UnidfnrSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.util.EjbLocalHelper;

import com.keyfactor.util.CertTools;

/** ASN.1 OCSP extension used to map a UNID to a Fnr, OID for this extension is 2.16.578.1.16.3.2
 * 
 * @version $Id$
 *
 */
public class OCSPUnidExtension implements OCSPExtension {

    public static final String OCSP_UNID_OID = "2.16.578.1.16.3.2";
    public static final String OCSP_UNID_NAME = "UnId Fnr";
    
	private static final Logger log = Logger.getLogger(OCSPUnidExtension.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    private CaSessionLocal caSession;
    private UnidfnrSessionLocal unidfnrSession;
    
    private int errCode = UnidFnrOCSPExtensionCode.ERROR_NO_ERROR.getValue();
    
    @Override
    public String getOid() {
        return OCSP_UNID_OID;
    }
    
    @Override
    public String getName() {
        return OCSP_UNID_NAME;
    }
    
    @Override
    public Set<OCSPExtensionType> getExtensionType() {
        return EnumSet.of(OCSPExtensionType.RESPONSE);
    }
    
	@Override
	public void init() {
        // Nothings need to be done here
	}
	
	@Override
	public Map<ASN1ObjectIdentifier, Extension> process(X509Certificate[] requestCertificates, String remoteAddress, String remoteHost,
            X509Certificate cert, CertificateStatus status, InternalKeyBinding internalKeyBinding) {

	    String serialNumber = null;
        String fnr = null;
        
        // Check authorization first
        if (!checkAuthorization(requestCertificates, remoteAddress, remoteHost, internalKeyBinding.getTrustedCertificateReferences())) {
        	errCode = UnidFnrOCSPExtensionCode.ERROR_UNAUTHORIZED.getValue();
        	return null;
        }
        // If the certificate is revoked, we must not return an FNR
        if (status != null) {
            errCode = UnidFnrOCSPExtensionCode.ERROR_CERT_REVOKED.getValue();
            return null;
        }
        
        // The Unid is in the DN component serialNumber
        serialNumber = CertTools.getPartFromDN(cert.getSubjectDN().getName(), "SN");
        if (serialNumber != null) {
            if (log.isDebugEnabled()) {
                log.debug("Found serialNumber: " + serialNumber);
            }
            String iMsg = intres.getLocalizedMessage("ocsp.receivedunidreq", remoteAddress, remoteHost, serialNumber);
            log.info(iMsg);

            // Make sure unidfnrSession is loaded properly in all environments before using it.
            if (unidfnrSession == null) {
                unidfnrSession = new EjbLocalHelper().getUnidfnrSession();
            }
            fnr = unidfnrSession.fetchUnidFnrData(serialNumber);
        } else {
            String errMsg = intres.getLocalizedMessage("ocsp.errorunidnosnindn", cert.getSubjectDN().getName());
            log.error(errMsg);
            errCode = UnidFnrOCSPExtensionCode.ERROR_NO_SERIAL_IN_DN.getValue();
            return null;
        }
        
        if (fnr == null) {
			String errMsg = intres.getLocalizedMessage("ocsp.errorunidnosnmapping", serialNumber);
            log.error(errMsg);
        	errCode = UnidFnrOCSPExtensionCode.ERROR_NO_FNR_MAPPING.getValue();
        	return null;
        }

        String successMsg = intres.getLocalizedMessage("ocsp.returnedunidresponse", remoteAddress, remoteHost, serialNumber);
        log.info(successMsg);
        
        return generateUnidFnrOCSPResponce(fnr);
	}
	
	/** Returns the last error that occurred during process(), when process returns null
	 * 
	 * @return error code as defined by implementing class
	 */
	public int getLastErrorCode() {
		return errCode;
	}
	
	private boolean checkAuthorization(X509Certificate[] certificates, String remoteAddress, String remoteHost, List<InternalKeyBindingTrustEntry> bindingTrustEntries) {
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
        boolean serialExists = false;
        final String issuerDN = CertTools.getIssuerDN(cert);
        
        // Make sure caSession is loaded properly in all environments before using it.
        if (caSession == null) {
            caSession = new EjbLocalHelper().getCaSession();
        }
        
        final CAInfo caInfo = caSession.getCAInfoInternal(issuerDN.hashCode());
        
        for (final InternalKeyBindingTrustEntry bindingTrustEntry : bindingTrustEntries) {
            // Match
            final BigInteger trustEntrySerial = bindingTrustEntry.fetchCertificateSerialNumber(); 
            if ((trustEntrySerial == null || trustEntrySerial.equals(cert.getSerialNumber())) && caInfo.getCAId() == bindingTrustEntry.getCaId()) {
                serialExists = true;
            }
        }
        
        if (serialExists) {
            // If we found in the hashmap the same key with issuer and serialnumber, we know we got it. 
            // Just verify it as well to be damn sure
            final Certificate cacert = caInfo.getCertificateChain().get(0);
            try {
                cert.verify(cacert.getPublicKey());
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

    private Map<ASN1ObjectIdentifier, Extension> generateUnidFnrOCSPResponce(final String fnr) {
        FnrFromUnidExtension ext = new FnrFromUnidExtension(fnr);
        HashMap<ASN1ObjectIdentifier, Extension> unidOCSPResponse = new HashMap<ASN1ObjectIdentifier, Extension>();
        try {
            unidOCSPResponse.put(FnrFromUnidExtension.FnrFromUnidOid, new Extension(FnrFromUnidExtension.FnrFromUnidOid, false, new DEROctetString(ext)));
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException caught.", e);
        }
        return unidOCSPResponse;
    }
}
