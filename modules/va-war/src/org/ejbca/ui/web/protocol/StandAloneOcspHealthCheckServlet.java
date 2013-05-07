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
package org.ejbca.ui.web.protocol;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.certificates.ocsp.cache.CryptoTokenAndChain;
import org.cesecore.certificates.ocsp.cache.OcspSigningCache;
import org.cesecore.certificates.ocsp.cache.OcspSigningCacheEntry;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.protocol.ocsp.OCSPUtil;
import org.ejbca.ui.web.pub.cluster.ValidationAuthorityHealthCheck;

/**
 * Currently a placeholder for the HealthCheck functionality which was extracted from OCSPStandAlone
 * 
 * 
 * See ECA-2630
 * 
 * @version $Id$
 *
 */
@Deprecated // TODO: Merge this with regular health-check
public class StandAloneOcspHealthCheckServlet extends HttpServlet implements IHealtChecker {

    private static final long serialVersionUID = -3256717200117000894L;

    private static final Logger log = Logger.getLogger(StandAloneOcspHealthCheckServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;

    @Override
    public void init(ServletConfig config) throws ServletException {
        // session must be created before health check could be done
        ValidationAuthorityHealthCheck.setHealtChecker(this);
    }

    @Override
    public String healthCheck(boolean doSignTest, boolean doValidityTest) {
        final StringWriter sw = new StringWriter();
        final PrintWriter pw = new PrintWriter(sw);
        try {
            final Collection<OcspSigningCacheEntry> ocspSigningCacheEntries = OcspSigningCache.INSTANCE.getEntries();
            if (ocspSigningCacheEntries.isEmpty()) {
                final String errMsg = intres.getLocalizedMessage("ocsp.errornosignkeys");
                pw.println();
                pw.print(errMsg);
                log.error(errMsg);
            } else {
                for (OcspSigningCacheEntry ocspSigningCacheEntry : ocspSigningCacheEntries) {
                    // Only verify non-CA responders
                    final X509Certificate ocspSigningCertificate = ocspSigningCacheEntry.getOcspSigningCertificate();
                    if (ocspSigningCertificate == null) {
                        continue;
                    }
                    final String subjectDn = CertTools.getSubjectDN(ocspSigningCacheEntry.getCaCertificateChain().get(0));
                    final String serialNumber = CertTools.getSerialNumber(ocspSigningCacheEntry.getOcspSigningCertificate()).toString(16);
                    final String errMsg = intres.getLocalizedMessage("ocsp.errorocspkeynotusable", subjectDn, serialNumber);
                    final PrivateKey privateKey = ocspSigningCacheEntry.getPrivateKey();
                    if (privateKey == null) {
                        pw.println();
                        pw.print(errMsg);
                        log.error("No key available. " + errMsg);
                        continue;
                    }
                    final String providerName = ocspSigningCacheEntry.getSignatureProviderName();
                    if (doValidityTest && !OCSPUtil.isCertificateValid(ocspSigningCertificate) ) {
                        pw.println();
                        pw.print(errMsg);
                        continue;
                    }
                    if (doSignTest) {
                        try {
                            KeyTools.testKey(privateKey, ocspSigningCertificate.getPublicKey(), providerName);
                        } catch (InvalidKeyException e) {
                            // thrown by testKey
                            pw.println();
                            pw.print(errMsg);
                            log.error("Key not working. SubjectDN '"+subjectDn+"'. Error comment '"+errMsg+"'. Message '"+e.getMessage());
                            continue;                   
                        }
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("Test of \""+errMsg+"\" OK!");                          
                    }
                }
            }
        } catch (Exception e) {
            final String errMsg = intres.getLocalizedMessage("ocsp.errorloadsigningcerts");
            log.error(errMsg, e);
            pw.print(errMsg + ": " + e.getMessage());
        }
        pw.flush();
        return sw.toString();
    }
}
