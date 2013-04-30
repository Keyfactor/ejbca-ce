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
import org.cesecore.keys.util.KeyTools;
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
            Collection<CryptoTokenAndChain> allCryptoTokenAndChainObjects = ocspResponseGeneratorSession.getCacheValues();
            if (allCryptoTokenAndChainObjects.size() == 0) {
                final String errMsg = intres.getLocalizedMessage("ocsp.errornosignkeys");
                pw.println();
                pw.print(errMsg);
                log.error(errMsg);
            } else {
                for (CryptoTokenAndChain cryptoTokenAndChain : allCryptoTokenAndChainObjects) {
                    X509Certificate[] certificateChain = cryptoTokenAndChain.getChain();
          
                    final String errMsg = intres.getLocalizedMessage("ocsp.errorocspkeynotusable", certificateChain[1].getSubjectDN(),
                            certificateChain[0].getSerialNumber().toString(16));
                    final PrivateKey privKey = cryptoTokenAndChain.getPrivateKey();
                    if (privKey == null) {
                        pw.println();
                        pw.print(errMsg);
                        log.error("No key available. " + errMsg);
                        continue;
                    }
                    final String providerName = cryptoTokenAndChain.getSignProviderName();
                    final X509Certificate entityCert = certificateChain[0]; 
                            //signingEntity.keyContainer.getCertificate(); // must be after getKey
         
                    if ( doValidityTest && !OCSPUtil.isCertificateValid(entityCert) ) {
                        pw.println();
                        pw.print(errMsg);
                        continue;
                    }
                    
                    if (doSignTest) {
                        try {
                            KeyTools.testKey(privKey, entityCert.getPublicKey(), providerName);
                        } catch (InvalidKeyException e) {
                            // thrown by testKey
                            pw.println();
                            pw.print(errMsg);
                            log.error("Key not working. SubjectDN '"+entityCert.getSubjectDN().toString()+"'. Error comment '"+errMsg+"'. Message '"+e.getMessage());
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
