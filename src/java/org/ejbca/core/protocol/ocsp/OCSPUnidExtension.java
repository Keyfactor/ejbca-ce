package org.ejbca.core.protocol.ocsp;

import java.security.cert.X509Certificate;
import java.util.Hashtable;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

/** OCSP extension used to map a UNID to a Fnr, OID for this extension is 2.16.578.1.16.3.2
 * 
 * @author tomas
 * @version $Id: OCSPUnidExtension.java,v 1.1 2006-02-05 15:51:02 anatom Exp $
 *
 */
public class OCSPUnidExtension implements IOCSPExtension {

    static private final Logger m_log = Logger.getLogger(OCSPUnidExtension.class);

	/** Called after construction
	 * 
	 * @param config ServletConfig that can be used to read init-params from web-xml
	 */
	public void init(ServletConfig config) {
	}
	
	/** Called by OCSP responder when the configured extension is found in the request.
	 * 
	 * @param request HttpServletRequest that can be used to find out information about caller, TLS certificate etc.
	 * @param cert X509Certificate the caller asked for in the OCSP request
	 * @return X509Extension that will be added to responseExtensions by OCSP responder, or null if an error occurs
	 */
	public Hashtable process(HttpServletRequest request, X509Certificate cert) {
		return null;
	}
	
	/** Returns the last error that occured during process(), when process returns null
	 * 
	 * @return error code as defined by implementing class
	 */
	public int getLastErrorCode() {
		return 0;
	}
}
