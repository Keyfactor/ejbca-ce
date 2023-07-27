/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util.provider;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;

import com.keyfactor.util.CertTools;

/**
 * This trust manager may be used used by a client that does not bother to verify the TLS certificate chain of the server.
 * Could be us used when you are fetching things from the server that are signed by the server (like certificates).
 * The class must not be used on the server side.
 *
 * @version  $Id$
 */
public class X509TrustManagerAcceptAll implements X509TrustManager {

    private static final Logger log = Logger.getLogger(X509TrustManagerAcceptAll.class);
    
    /**
     */
    public X509TrustManagerAcceptAll() {
    }

    /* (non-Javadoc)
     * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // do nothing
        if (log.isDebugEnabled()) {
            log.debug("checkClientTrusted: SubjectDN: " + CertTools.getSubjectDN(chain[0]));
            log.debug("checkClientTrusted: IssuerDN:  " + CertTools.getIssuerDN(chain[0]));
        }
    }

    /* (non-Javadoc)
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // do nothing
        if (log.isDebugEnabled()) {
            log.debug("checkServerTrusted: SubjectDN: " + CertTools.getSubjectDN(chain[0]));
            log.debug("checkServerTrusted: IssuerDN:  " + CertTools.getIssuerDN(chain[0]));
        }
    }

    /* (non-Javadoc)
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        // only called from server side
        if (log.isTraceEnabled()) {
            log.trace(">getAcceptedIssuers (returning null)");
        }
        return null;
    }

}
