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
 
package org.ejbca.ui.web.pub.retrieve;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.caadmin.CaSession;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.util.CertTools;

/**
 * This bean performs a number of certificate searches for the public web.
 * 
 * To make it easy to use from JSTL pages, most methods take no arguments.
 * The arguments are supplied as member variables instead. <br>
 * 
 * @author Rolf Staflin
 * @version $Id$
 */
public class CertificateFinderBean {
	
	private static final Logger log = Logger.getLogger(CertificateFinderBean.class);

	private EjbLocalHelper ejb = new EjbLocalHelper();
	private SignSession mSignSession = ejb.getSignSession();
	private CAAdminSession mCaAdminSession = ejb.getCaAdminSession();
	private CaSession caSession = ejb.getCaSession();
	private CertificateStoreSession mStoreSession = ejb.getCertificateStoreSession();

	private boolean mInitialized = false;
	private Admin mAdmin;
	
	/** This member is used by the JSP pages to indicate which CA they are interested in. 
	 * It is used by getCAInfo().
	 */
	private int mCurrentCA;

	/**
	 * Empty default constructor.
	 * NOTE: Call initialize() after creating this object.
	 */
	public CertificateFinderBean() { }
	
	/**
	 * Initializes all the session beans used by this ocject.
	 * This method must be called before other methods.
	 * <p>Call it like this:
	 * <br><tt>&lt;% finder.initialize(request.getRemoteAddr()); %&gt</tt>
	 * 
	 * @param remoteAddress The remote address as supplied by the request JSP object.
	 */
	public void initialize(String remoteAddress) {
		log.trace(">initialize()");
	    mAdmin = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteAddress);
	    mInitialized = true;
	}

	public Collection<Integer> getAvailableCAs() {
	    if(log.isTraceEnabled()) {
		log.trace(">getAvailableCAs()");
	    }
		return mInitialized ? caSession.getAvailableCAs(mAdmin) : null;
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
			log.trace(">getCAInfo() currentCA = " + mCurrentCA + ", initialized == " + mInitialized);
		}
		return mInitialized ? mCaAdminSession.getCAInfo(mAdmin, mCurrentCA) : null;
	}

	public Collection<CertificateWrapper> getCACertificateChain() {
		if (log.isTraceEnabled()) {
			log.trace(">getCACertificateChain() currentCA = " + mCurrentCA + ", initialized == " + mInitialized);
		}
		if (!mInitialized) {
			return null;
		}
		// Make a collection of CertificateWrapper instead of the real certificate
		ArrayList<CertificateWrapper> ret = new ArrayList<CertificateWrapper>();
		Collection<Certificate> certs = mSignSession.getCertificateChain(mAdmin, mCurrentCA);
		for (Iterator<Certificate> it = certs.iterator(); it.hasNext();) {
			Certificate cert = (Certificate)it.next();
			ret.add(new CertificateWrapper(cert));
		}
		return ret;
	}

	public String getCADN() {
		final Collection<Certificate> certs = this.mSignSession.getCertificateChain(this.mAdmin, this.mCurrentCA);
		if ( certs==null || certs.isEmpty() ) {
			return "";
		}
		final Certificate cert = (Certificate)certs.iterator().next();
		return CertTools.getSubjectDN(cert);
	}

	public Collection<CertificateWrapper> getCACertificateChainReversed() {
		Collection<CertificateWrapper> ret = getCACertificateChain();
		if (ret != null) {
			Collections.reverse((ArrayList<CertificateWrapper>) ret);
		}
		return ret;
	}
	
	public boolean getOcspEnabled() {
		CAInfo caInfo = getCAInfo();
		boolean active = false;
		if (caInfo != null) {
			Iterator<ExtendedCAServiceInfo> iter = caInfo.getExtendedCAServiceInfos().iterator();
			while(iter.hasNext()){
		      ExtendedCAServiceInfo next = (ExtendedCAServiceInfo) iter.next();
		      if(next instanceof OCSPCAServiceInfo){
		      	active = next.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE;
		      }
			}			
		} else {
			log.debug("getOcspEnabled: caInfo is null");
		}
		return active;
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
		if (result == null || mInitialized == false) {
			return; // There's nothing we can do here.
		}
		try {
			BigInteger serialBignum = new BigInteger(Hex.decode(StringUtils.trimToEmpty(serialNumber)));			
			CertificateStatus info = mStoreSession.getStatus(StringUtils.trimToEmpty(issuerDN), serialBignum);
			if (info == null) {
				result.setRevocationDate(null);
				result.setUserCertificate(null);
			} else {
				result.setReason(info.revocationReason);
				result.setRevocationDate(info.revocationDate);
				result.setUserCertificate(serialBignum);
			}
		} catch (StringIndexOutOfBoundsException e) {
			log.error("Invalid serial number entered: "+serialNumber);
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
		if (subject == null || mInitialized == false) {
			return; // We can't lookup any certificates, so return with an empty result.
		}
		Collection<Certificate> certificates = mStoreSession.findCertificatesBySubject(mAdmin, subject);
		if (certificates != null) {
			Iterator<Certificate> i = certificates.iterator();
			while (i.hasNext()) {
				Certificate cert = i.next();
				// TODO: CertificateView is located in web.admin package, but this is web.pub package...
				CertificateView view = new CertificateView(cert,null,null);
				result.add(view);
			}
		}
	}
}
