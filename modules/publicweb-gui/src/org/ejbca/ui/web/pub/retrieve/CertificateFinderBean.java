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
 
package org.ejbca.ui.web.pub.retrieve;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.util.CertTools;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.CertificateView;

/**
 * This bean performs a number of certificate searches for the public web.
 * 
 * To make it easy to use from JSTL pages, most methods take no arguments.
 * The arguments are supplied as member variables instead. <br>
 * 
 * @version $Id$
 */
public class CertificateFinderBean {
	
	private static final Logger log = Logger.getLogger(CertificateFinderBean.class);

	private EjbLocalHelper ejb = new EjbLocalHelper();
	private SignSession mSignSession = ejb.getSignSession();
	private CaSessionLocal caSession = ejb.getCaSession();
	private CertificateStoreSessionLocal mStoreSession = ejb.getCertificateStoreSession();
	
	/** This member is used by the JSP pages to indicate which CA they are interested in. 
	 * It is used by getCAInfo().
	 */
	private int mCurrentCA;
	
    // Used to store the result of lookupCertificateInfo
    private String issuerDN;
    private String subjectDN;
    private String serialNumber;

	/**
	 * Empty default constructor.
	 * NOTE: Call initialize() after creating this object.
	 */
	public CertificateFinderBean() { }
	
	public Collection<Integer> getAvailableCAs() {
	    if(log.isTraceEnabled()) {
		log.trace(">getAvailableCAs()");
	    }
		return  caSession.getAllCaIds();
	}

	public int getCurrentCA() {
		return mCurrentCA;
	}

	public void setCurrentCA(Integer currentCA) {
		if (log.isTraceEnabled()) {
			log.trace(">setCurrentCA(" + currentCA + ")");
		}
		mCurrentCA = currentCA;
	}

	public CAInfo getCAInfo() {
		if (log.isTraceEnabled()) {
			log.trace(">getCAInfo() currentCA = " + mCurrentCA);
		}
		CAInfo cainfo = null;
		try {
			cainfo = caSession.getCAInfoInternal(mCurrentCA);
		} catch (CADoesntExistsException e) {
			log.info("CA does not exist : "+mCurrentCA, e);
		} 
		return cainfo;
	}

	public Collection<CertificateGuiInfo> getCACertificateChain() {
		if (log.isTraceEnabled()) {
			log.trace(">getCACertificateChain() currentCA = " + mCurrentCA);
		}
		// Make a collection of CertificateGuiInfo instead of the real certificate
		ArrayList<CertificateGuiInfo> ret = new ArrayList<CertificateGuiInfo>();
        Collection<Certificate> certs = mSignSession.getCertificateChain(mCurrentCA);
        for (Certificate cert : certs) {
            ret.add(new CertificateGuiInfo(cert));
        }
		
		return ret;
	}
	
	   public Collection<CertificateGuiInfo> getCACertificateChainReversed() {
	        Collection<CertificateGuiInfo> ret = getCACertificateChain();
	        if (ret != null) {
	            Collections.reverse((ArrayList<CertificateGuiInfo>) ret);
	        }
	        return ret;
	    }

	public String getCADN() {
		String ret = "Unauthorized";
			final Collection<Certificate> certs = this.mSignSession.getCertificateChain(this.mCurrentCA);
			if ( certs==null || certs.isEmpty() ) {
				return "";
			}
			final Certificate cert = (Certificate)certs.iterator().next();
			ret = CertTools.getSubjectDN(cert);
		
		return ret;
	}


	
	/**
	 * Get revocation info for a certificate.
	 * This method fills in the supplied RevokedCertInfo object with data about a certificate.
	 * Since Java uses "call by reference" this works fine, but we can't create our own object because
	 * the caller doesn't read the reference when unwinding the stack after this method returns.
	 * 
	 * @param issuerDN DN of the certificate's issuer
	 * @param serialNumber The serial number of the certificate
	 * @param result An allocated object. Data about the certificate is entered in the result object by this method.
	 *        If no info can be found (e.g., if the certificate does not exist), the revocationDate and
	 *        userCertificate fields of result are set to null. 
	 */
	public void lookupRevokedInfo(String issuerDN, String serialNumber, RevokedCertInfo result) {
		serialNumber = ("0000000000000000" + serialNumber).substring(serialNumber.length());	// Pad with zeroes up to 16 chars
		if (log.isTraceEnabled()) {
			log.trace(">lookupRevokedInfo(" + issuerDN + ", " + serialNumber + ", " + result + ")");
		}
		if (result == null) {
			return; // There's nothing we can do here.
		}
		try {
			BigInteger serialBignum = new BigInteger(Hex.decode(StringUtils.trimToEmpty(serialNumber)));			
			CertificateStatus info = mStoreSession.getStatus(StringUtils.trimToEmpty(issuerDN), serialBignum);
			if (info.equals(CertificateStatus.NOT_AVAILABLE)) {
				result.setRevocationDate(null);
				result.setUserCertificate(null);
			} else {
				result.setReason(info.revocationReason);
				result.setRevocationDate(info.revocationDate);
				result.setUserCertificate(serialBignum);
			}
        } catch (NumberFormatException e) {
            log.info("Invalid serial number entered (NumberFormatException): "+serialNumber+": "+e.getMessage());
		} catch (StringIndexOutOfBoundsException e) {
			log.info("Invalid serial number entered (StringIndexOutOfBoundsException): "+serialNumber+": "+e.getMessage());
		} catch (DecoderException e) {
            log.info("Invalid serial number entered (DecoderException): "+serialNumber+": "+e.getMessage());		    
		}
	}

	/**
	 * Uses the store session to look up all certificates for a subject.
	 * The parameter <code>result</code> is updated so that it contains
	 * the certificates as CertificateView objects.
	 * @param subject The DN of the subject
	 * @param result a Collection (not null) that will be filled by CertificateView objects
	 */
	public void lookupCertificatesBySubject(String subject, Collection<CertificateView> result) {
		if (log.isTraceEnabled()) {
			log.trace(">lookupCertificatesBySubject(" + subject + ", " + result + ")");
		}
		if (result == null) {
			return; // There's nothing we can do here.
		}
		result.clear();
		if (subject == null) {
			return; // We can't lookup any certificates, so return with an empty result.
		}
		final List<CertificateDataWrapper> cdws = mStoreSession.getCertificateDatasBySubject(subject);
		Collections.sort(cdws);
		for (final CertificateDataWrapper cdw : cdws) {
            // TODO: CertificateView is located in web.admin package, but this is web.pub package...
            result.add(new CertificateView(cdw));
		}
	}
	
	/**
	 * Looks up a certificate information by issuer and serial number.
	 * The information can be accessed by getter methods in this class.
	 * @see getIssuerDN()
	 * @see getSubjectDN()
	 * @see getSerialNumber()
	 */
    public void lookupCertificateInfo(String issuer, String serno) {
        BigInteger sernoBigInt = CertTools.getSerialNumberFromString(serno);
        Certificate cert = mStoreSession.findCertificateByIssuerAndSerno(issuer, sernoBigInt);
        if (cert != null) {
            this.issuerDN = CertTools.getIssuerDN(cert);
            this.subjectDN = CertTools.getSubjectDN(cert);
            this.serialNumber = CertTools.getSerialNumberAsString(cert);
        }
    }
    
    /**
     * @return the Issuer DN string of the current certificate.
     * @see lookupCertificateInfo(String, String)
     */
    public String getIssuerDN() {
        return issuerDN;
    }
    
    /**
     * @return the Subject DN string of the current certificate.
     * @see lookupCertificateInfo(String, String)
     */
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * @return the Subject DN string of the current certificate URL-encoded using the current 
     * @see lookupCertificateInfo(String, String)
     */
    public String getSubjectDNEncoded() {
        return getHttpParamAsUrlEncoded(subjectDN);
    }

    /**
     * @return the serial number hex string of the current certificate.
     * @see lookupCertificateInfo(String, String)
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /** @return the param as it's URL encoded counterpart, taking the configured encoding into account. */
    private String getHttpParamAsUrlEncoded(final String param) {
        final String encoding = WebConfiguration.getWebContentEncoding();
        try {
            return URLEncoder.encode(param, encoding);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("The property 'web.contentencoding' is set to " + encoding + ", but this encoding is not available on this system.", e);
        }
    }
}
