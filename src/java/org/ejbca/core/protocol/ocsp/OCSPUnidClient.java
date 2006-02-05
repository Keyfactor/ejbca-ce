package org.ejbca.core.protocol.ocsp;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

/** A simple OCSP lookup client used to query the OCSPUnidExtension
 * 
 * @author tomas
 * @version $Id: OCSPUnidClient.java,v 1.1 2006-02-05 15:51:02 anatom Exp $
 *
 */
public class OCSPUnidClient {

	/** 
	 * 
	 * @param ks KeyStore client keystore used to authenticate TLS client authentication
	 */
	public OCSPUnidClient(KeyStore ks) {
		// TODO:
	}
	
	/**
	 * 
	 * @param cert X509Certificate to query, the DN should contain serialNumber which is Unid
	 * @param cacert X509Certificate to query, the DN should contain serialNumber which is Unid
	 * @param ocspurl String url to the OCSP server, e.g. http://127.0.0.1:8080/ejbca/publicweb/status/ocsp 
	 * @param getfnr if we should ask for a Unid-Fnr mapping or only query the OCSP server
	 * @return OCSPUnidResponse
	 */
	public OCSPUnidResponse lookup(X509Certificate cert, X509Certificate cacert, String ocspurl, boolean getfnr) {	
		// TODO:
		return null;
	}
}
