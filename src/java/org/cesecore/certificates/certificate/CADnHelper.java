/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.security.cert.Certificate;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.util.CertTools;

/**
 * Helper class with method broken out from CertificateCreateSessionBean as it 
 * was used directly from an other class.
 * 
 * @version $Id$
 */
public class CADnHelper {
    
    private static final Logger log = Logger.getLogger(CADnHelper.class);
    
    /** Tries to get an issuerDN/serialNumber pair from the request, and see if we have that CA certificate in the certificate store. If we have
     * the CA dn, in CESeCore normalized for is returned. 
     * @param req the request message that might contain an issued DN
     * @return issuer DN or null if it does not exist in the 
     */
    public static String getCADnFromRequest(final RequestMessage req, final CertificateStoreSession certificateStoreSession) {
        String dn = req.getIssuerDN();
        if (log.isDebugEnabled()) {
            log.debug("Got an issuerDN: " + dn);
        }
        // If we have issuer and serialNo, we must find the CA certificate, to get the CAs subject name
        // If we don't have a serialNumber, we take a chance that it was actually the subjectDN (for example a RootCA)
        final BigInteger serno = req.getSerialNo();
        if (serno != null) {
            if (log.isDebugEnabled()) {
                log.debug("Got a serialNumber: " + serno.toString(16));
            }

            final Certificate cert = certificateStoreSession.findCertificateByIssuerAndSerno(dn, serno);
            if (cert != null) {
                dn = CertTools.getSubjectDN(cert);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Using DN: " + dn);
        }
        return dn;
    }
}
