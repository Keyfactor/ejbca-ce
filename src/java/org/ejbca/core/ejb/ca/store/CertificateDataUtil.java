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
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.ejb.EJBException;
import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;

/** Code from CertificateStoreSessionBean that should be available in the stand-alone VA. 
 * We want to avoid having methods that can update things on the VA.
 * 
 * @version $Id$
 */
public abstract class CertificateDataUtil {
	
	// 
	// TODO: The methods in this class are copy-paste from CertificateStoreSessionBean, very bad!
	//
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    private static final Logger LOG = Logger.getLogger(CertificateDataUtil.class);
    
    protected Certificate findCertificateByFingerprint(AuthenticationToken admin, String fingerprint, EntityManager entityManager) {
        if (LOG.isTraceEnabled()) {
        	LOG.trace(">findCertificateByFingerprint()");
        }
        Certificate ret = null;
        try {
        	CertificateData res = CertificateData.findByFingerprint(entityManager, fingerprint);
        	if (res != null) {
                ret = res.getCertificate();
        	}
        } catch (Exception e) {
        	LOG.error("Error finding certificate with fp: " + fingerprint);
            throw new EJBException(e);
        }
        if (LOG.isTraceEnabled()) {
        	LOG.trace("<findCertificateByFingerprint()");
        }
        return ret;
    }

    protected Certificate findCertificateByIssuerAndSerno(String issuerDN, BigInteger serno, EntityManager entityManager) {
        if (LOG.isTraceEnabled()) {
        	LOG.trace(">findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        if (LOG.isDebugEnabled()) {
        	LOG.debug("Looking for cert with (transformed)DN: " + dn);
        }
        Collection<CertificateData> coll = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
        Certificate ret = null;
        if (coll.size() > 1) {
        	String msg = intres.getLocalizedMessage("store.errorseveralissuerserno", issuerDN, serno.toString(16));
        	LOG.error(msg);
        	//adapter.log(admin, issuerDN.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_DATABASE, msg);	
        }
        Iterator<CertificateData> iter = coll.iterator();
        Certificate cert = null;
        // There are several certs, we will try to find the latest issued one
        if (iter.hasNext()) {
        	cert = iter.next().getCertificate();
        	if (ret != null) {
        		if (CertTools.getNotBefore(cert).after(CertTools.getNotBefore(ret))) {
        			// cert is never than ret
        			ret = cert;
        		}
        	} else {
        		ret = cert;
        	}
        }
        if (LOG.isTraceEnabled()) {
        	LOG.trace("<findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        return ret;
    }

    protected Collection<Certificate> findCertificatesByType(int type, String issuerDN, EntityManager entityManager) throws IllegalArgumentException {
        if (LOG.isTraceEnabled()) {
        	LOG.trace(">findCertificatesByType()");
        }
        if (type <= 0
                || type > CertificateConstants.CERTTYPE_SUBCA + CertificateConstants.CERTTYPE_ENDENTITY + CertificateConstants.CERTTYPE_ROOTCA) {
            throw new IllegalArgumentException();
        }
        final StringBuilder ctypes = new StringBuilder();
        if ((type & SecConst.CERTTYPE_SUBCA) > 0) {
            ctypes.append(SecConst.CERTTYPE_SUBCA);
        }
        if ((type & SecConst.CERTTYPE_ENDENTITY) > 0) {
            if (ctypes.length() > 0) {
                ctypes.append(", ");
            }
            ctypes.append(SecConst.CERTTYPE_ENDENTITY);
        }
        if ((type & SecConst.CERTTYPE_ROOTCA) > 0) {
            if (ctypes.length() > 0) {
                ctypes.append(", ");
            }
            ctypes.append(SecConst.CERTTYPE_ROOTCA);
        }
        List<Certificate> ret;
        if (null != issuerDN && issuerDN.length() > 0) {
        	ret = CertificateData.findActiveCertificatesByTypeAndIssuer(entityManager, ctypes.toString(), CertTools.stringToBCDNString(issuerDN));
        } else {
        	ret = CertificateData.findActiveCertificatesByType(entityManager, ctypes.toString());
        }
        if (LOG.isTraceEnabled()) {
        	LOG.trace("<findCertificatesByType()");
        }
        return ret;
    }
    
    protected Collection<Certificate> findCertificatesByUsername(String username, EntityManager entityManager) {
    	if (LOG.isTraceEnabled()) {
    		LOG.trace(">findCertificatesByUsername(),  username=" + username);
    	}
    	// Strip dangerous chars
    	username = StringTools.strip(username);
    	// This method on the entity bean does the ordering in the database
    	Collection<CertificateData> coll = CertificateData.findByUsernameOrdered(entityManager, username);
    	ArrayList<Certificate> ret = new ArrayList<Certificate>();
    	Iterator<CertificateData> iter = coll.iterator();
    	while (iter.hasNext()) {
    		ret.add(iter.next().getCertificate());
    	}
    	if (LOG.isTraceEnabled()) {
    		LOG.trace("<findCertificatesByUsername(), username=" + username);
    	}
    	return ret;
    }


    protected CertificateStatus getStatus(String issuerDN, BigInteger serno, EntityManager entityManager) {
        if (LOG.isTraceEnabled()) {
        	LOG.trace(">getStatus(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First make a DN in our well-known format
        final String dn = CertTools.stringToBCDNString(issuerDN);

        try {
        	Collection<CertificateData> coll = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
        	if (coll.size() > 1) {
        		String msg = intres.getLocalizedMessage("store.errorseveralissuerserno", issuerDN, serno.toString(16));            	
        		//adapter.log(admin, issuerDN.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_DATABASE, msg);
        		LOG.error(msg);
        	}
        	Iterator<CertificateData> iter = coll.iterator();
        	if (iter.hasNext()) {
        		final CertificateData data = iter.next();
        		final CertificateStatus result = getIt(data);
        		if (LOG.isTraceEnabled()) {
        			LOG.trace("<getStatus() returned " + result + " for cert number "+serno.toString(16));
        		}
        		return result;
        	}
            if (LOG.isTraceEnabled()) {
            	LOG.trace("<getStatus() did not find certificate with dn "+dn+" and serno "+serno.toString(16));
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        return CertificateStatus.NOT_AVAILABLE;
    }
    
    /** Algorithm:
     * if status is CERT_REVOKED the certificate is revoked and reason and date is picked up
     * if status is CERT_ARCHIVED and reason is _NOT_ REMOVEFROMCRL or NOT_REVOKED the certificate is revoked and reason and date is picked up
     * if status is CERT_ARCHIVED and reason is REMOVEFROMCRL or NOT_REVOKED the certificate is NOT revoked
     * if status is neither CERT_REVOKED or CERT_ARCHIVED the certificate is NOT revoked
     * 
     * @param data
     * @return CertificateStatus, can be compared (==) with CertificateStatus.OK, CertificateStatus.REVOKED and CertificateStatus.NOT_AVAILABLE
     */
    protected CertificateStatus getIt(CertificateData data) {
    	if ( data == null ) {
    		return CertificateStatus.NOT_AVAILABLE;
    	}
    	final int pId; {
    		final Integer tmp=data.getCertificateProfileId();
    		pId = tmp!=null ? tmp.intValue() : CertificateProfileConstants.CERTPROFILE_NO_PROFILE;
    	}
    	final int status = data.getStatus();
    	if ( status==SecConst.CERT_REVOKED ) {
    		return new CertificateStatus(data.getRevocationDate(), data.getRevocationReason(), pId);
    	}
    	if ( status!=SecConst.CERT_ARCHIVED ) {
    		return new CertificateStatus(CertificateStatus.OK.toString(), pId);
    	}
    	// If the certificate have status ARCHIVED, BUT revocationReason is REMOVEFROMCRL or NOTREVOKED, the certificate is OK
    	// Otherwise it is a revoked certificate that has been archived and we must return REVOKED
    	final int revReason = data.getRevocationReason(); // Read revocationReason from database if we really need to..
    	if ( revReason==RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL || revReason==RevokedCertInfo.NOT_REVOKED ) {
    		return new CertificateStatus(CertificateStatus.OK.toString(), pId);
    	}
    	return new CertificateStatus(data.getRevocationDate(), revReason, pId);
    }
}
