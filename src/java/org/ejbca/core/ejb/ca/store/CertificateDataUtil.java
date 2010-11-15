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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.ejb.EJBException;
import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;

/** Common code between CertificateStoreSessionBean and CertificateStoreOnlyDataSessionBean
 * 
 * @author lars
 * @version $Id$
 */
public class CertificateDataUtil {
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    public interface Adapter {
        void debug( String s );
        void error( String s );
        void error( String s, Exception e );
        Logger getLogger();
        void log(Admin admin, int caid, int module, Date time, String username,
                 X509Certificate certificate, int event, String comment);
    }

    public static Certificate findCertificateByFingerprint(Admin admin, String fingerprint, EntityManager entityManager, Adapter adapter) {
        adapter.getLogger().trace(">findCertificateByFingerprint()");
        Certificate ret = null;
        try {
        	CertificateData res = CertificateData.findByFingerprint(entityManager, fingerprint);
        	if (res != null) {
                ret = res.getCertificate();
        	}
        } catch (Exception e) {
            adapter.getLogger().error("Error finding certificate with fp: " + fingerprint);
            throw new EJBException(e);
        }
        adapter.getLogger().trace("<findCertificateByFingerprint()");
        return ret;
    }

    public static Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno, EntityManager entityManager, Adapter adapter) {
        if (adapter.getLogger().isTraceEnabled()) {
        	adapter.getLogger().trace(">findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        if (adapter.getLogger().isDebugEnabled()) {
        	adapter.debug("Looking for cert with (transformed)DN: " + dn);
        }
        Collection<CertificateData> coll = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
        Certificate ret = null;
        if (coll.size() > 1) {
        	String msg = intres.getLocalizedMessage("store.errorseveralissuerserno", issuerDN, serno.toString(16));            	
        	adapter.log(admin, issuerDN.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_DATABASE, msg);	
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
        if (adapter.getLogger().isTraceEnabled()) {
        	adapter.getLogger().trace("<findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        return ret;
    }

    public static Collection<Certificate> findCertificatesByType(Admin admin, int type, String issuerDN,
                                                    EntityManager entityManager,
                                                    Adapter adapter) throws IllegalArgumentException {
        adapter.getLogger().trace(">findCertificatesByType()");
        if (null == admin
                || type <= 0
                || type > SecConst.CERTTYPE_SUBCA + SecConst.CERTTYPE_ENDENTITY + SecConst.CERTTYPE_ROOTCA) {
            throw new IllegalArgumentException();
        }
        StringBuffer ctypes = new StringBuffer();
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
        adapter.getLogger().trace("<findCertificatesByType()");
        return ret;
    }
    
    public static Collection<Certificate> findCertificatesByUsername(Admin admin, String username, EntityManager entityManager, Adapter adapter) {
    	if (adapter.getLogger().isTraceEnabled()) {
    		adapter.getLogger().trace(">findCertificatesByUsername(),  username=" + username);
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
    	if (adapter.getLogger().isTraceEnabled()) {
    		adapter.getLogger().trace("<findCertificatesByUsername(), username=" + username);
    	}
    	return ret;
    }


    static public CertificateStatus getStatus(String issuerDN, BigInteger serno, EntityManager entityManager, Adapter adapter) {
        if (adapter.getLogger().isTraceEnabled()) {
            adapter.getLogger().trace(">getStatus(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First make a DN in our well-known format
        final String dn = CertTools.stringToBCDNString(issuerDN);

        try {
        	Collection<CertificateData> coll = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
        	if (coll.size() > 1) {
        		String msg = intres.getLocalizedMessage("store.errorseveralissuerserno", issuerDN, serno.toString(16));            	
        		//adapter.log(admin, issuerDN.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_DATABASE, msg);
        		adapter.error(msg);
        	}
        	Iterator<CertificateData> iter = coll.iterator();
        	if (iter.hasNext()) {
        		final CertificateData data = iter.next();
        		final CertificateStatus result = getIt(data);
        		if (adapter.getLogger().isTraceEnabled()) {
        			adapter.getLogger().trace("<getStatus() returned " + result + " for cert number "+serno.toString(16));
        		}
        		return result;
        	}
            if (adapter.getLogger().isTraceEnabled()) {
            	adapter.getLogger().trace("<getStatus() did not find certificate with dn "+dn+" and serno "+serno.toString(16));
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
    private final static CertificateStatus getIt(CertificateData data) {
    	if ( data == null ) {
    		return CertificateStatus.NOT_AVAILABLE;
    	}
    	final int pId; {
    		final Integer tmp=data.getCertificateProfileId();
    		pId = tmp!=null ? tmp.intValue() : SecConst.CERTPROFILE_NO_PROFILE;
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
    	if ( revReason==RevokedCertInfo.REVOKATION_REASON_REMOVEFROMCRL || revReason==RevokedCertInfo.NOT_REVOKED ) {
    		return new CertificateStatus(CertificateStatus.OK.toString(), pId);
    	}
    	return new CertificateStatus(data.getRevocationDate(), revReason, pId);
    }
}
