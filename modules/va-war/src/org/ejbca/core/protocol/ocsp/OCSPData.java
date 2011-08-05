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
package org.ejbca.core.protocol.ocsp;

import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.util.CertTools;
import org.ejbca.config.OcspConfiguration;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.certificatestore.HashID;
import org.ejbca.core.protocol.certificatestore.ICertificateCache;

/**
 * Data to be used both in servlet and session object.
 * 
 * @author primelars
 * @version  $Id$
 */
public class OCSPData {

    final public CertificateStoreSessionLocal certificateStoreSession;

    private static final Logger m_log = Logger.getLogger(OCSPData.class);

    public final Admin m_adm = Admin.getInternalAdmin();

    /** Cache time counter, set and used by loadPrivateKeys (external responder) */
    public long mKeysValidTo = 0;

    /** Cache of CA certificates (and chain certs) for CAs handles by this responder */
    public ICertificateCache m_caCertCache = null;

    /** String used to identify default responder id, used to generate responses when a request
     * for a certificate not signed by a CA on this server is received.
     */
    public final String m_defaultResponderId = OcspConfiguration.getDefaultResponderId();

    public OCSPData(CertificateStoreSessionLocal certificateStoreSession) {
        this.certificateStoreSession = certificateStoreSession;
    }
    /** Generates an EJBCA caid from a CA certificate, or looks up the default responder certificate.
     * 
     * @param cacert the CA certificate to get the CAid from. If this is null, the default responder CA cert  is looked up and used
     * @return int 
     */
     public int getCaid( X509Certificate cacert ) {
        X509Certificate cert = cacert;
        if (cacert == null) {
            m_log.debug("No correct CA-certificate available to sign response, signing with default CA: "+this.m_defaultResponderId);
            cert = this.m_caCertCache.findLatestBySubjectDN(HashID.getFromDN(this.m_defaultResponderId));           
        }

        int result = CertTools.stringToBCDNString(cert.getSubjectDN().toString()).hashCode();
        if (m_log.isDebugEnabled()) {
            m_log.debug( cert.getSubjectDN() + " has caid: " + result );
        }
        return result;
    }
}
