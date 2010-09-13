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
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.naming.NamingException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.util.EjbRemoteHelper;
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

	private EjbRemoteHelper ejb = new EjbRemoteHelper();
	private SignSessionRemote mSignSession = ejb.getSignSession();
	private CAAdminSessionRemote mCaAdminSession = ejb.getCAAdminSession();
	private CertificateStoreSessionRemote mStoreSession = ejb.getCertStoreSession();

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
	public CertificateFinderBean() {
	}
	
	/**
	 * Initializes all the session beans used by this ocject.
	 * This method must be called before other methods.
	 * <p>Call it like this:
	 * <br><tt>&lt;% finder.initialize(request.getRemoteAddr()); %&gt</tt>
	 * 
	 * @param remoteAddress The remote address as supplied by the request JSP object.
	 * @throws NamingException If context related errors occur.
	 * @throws RemoteException If session bean creation fails.
	 * @throws CreateException If session bean creation fails.
	 */
	public void initialize(String remoteAddress) throws NamingException, RemoteException, CreateException {
		log.trace(">initialize()");
	    mAdmin = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteAddress);
	    mInitialized = true;
	}

	public Collection getAvailableCAs() throws RemoteException {
		log.trace(">getAvailableCAs()");
		return mInitialized ? mCaAdminSession.getAvailableCAs(mAdmin) : null;
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

	public CAInfo getCAInfo() throws RemoteException {
		if (log.isTraceEnabled()) {
			log.trace(">getCAInfo() currentCA = " + mCurrentCA + ", initialized == " + mInitialized);
		}
		return mInitialized ? mCaAdminSession.getCAInfo(mAdmin, mCurrentCA) : null;
	}

	public Collection getCACertificateChain() throws RemoteException {
		if (log.isTraceEnabled()) {
			log.trace(">getCACertificateChain() currentCA = " + mCurrentCA + ", initialized == " + mInitialized);
		}
		if (!mInitialized) {
			return null;
		}
		// Make a collection of CertificateWrapper instead of the real certificate
		ArrayList ret = new ArrayList();
		Collection certs = mSignSession.getCertificateChain(mAdmin, mCurrentCA);
		for (Iterator it = certs.iterator(); it.hasNext();) {
			Certificate cert = (Certificate)it.next();
			ret.add(new CertificateWrapper(cert));
		}
		return ret;
	}

	public String getCADN() throws RemoteException {
		final Collection certs = this.mSignSession.getCertificateChain(this.mAdmin, this.mCurrentCA);
		if ( certs==null || certs.isEmpty() ) {
			return "";
		}
		final Certificate cert = (Certificate)certs.iterator().next();
		return CertTools.getSubjectDN(cert);
	}

	public Collection getCACertificateChainReversed() throws RemoteException {
		Collection ret = getCACertificateChain();
		if (ret != null) {
			Collections.reverse((ArrayList) ret);
		}
		return ret;
	}
	
	public boolean getOcspEnabled() throws RemoteException {
		CAInfo caInfo = getCAInfo();
		boolean active = false;
		if (caInfo != null) {
			Iterator iter = caInfo.getExtendedCAServiceInfos().iterator();
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
	 * @throws RemoteException If a communication error occurs while looking up the info.
	 */
	public void lookupRevokedInfo(String issuerDN, String serialNumber, RevokedCertInfo result) throws RemoteException {
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
	 * @throws RemoteException
	 */
	@SuppressWarnings("unchecked")
	public void lookupCertificatesBySubject(String subject, Collection result) throws RemoteException {
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
		Collection certificates = mStoreSession.findCertificatesBySubject(mAdmin, subject);
		if (certificates != null) {
			Iterator i = certificates.iterator();
			while (i.hasNext()) {
				Certificate cert = (Certificate)i.next();
				// TODO: CertificateView is located in web.admin package, but this is web.pub package...
				CertificateView view = new CertificateView(cert,null,null);
				result.add(view);
			}
		}
	}
}
