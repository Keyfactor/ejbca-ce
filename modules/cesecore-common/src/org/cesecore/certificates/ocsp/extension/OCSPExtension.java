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

package org.cesecore.certificates.ocsp.extension;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateStatus;

/**
 * Interface that must be implemented by OCSP extensions that are added to the OCSPServlet
 * 
 * @version $Id$
 */
public interface OCSPExtension {

    /** Called after construction
     * 
     */
    void init();

    /**
     * Called by OCSP responder when the configured extension is found in the request.
     * 
     * @param requestCertificates
     *            A certificate array from the original HttpServletRequest, used for authorization.
     * @param remoteAddress
     *            Extracted from the HttpServletRequest.
     * @param remoteHost
     *            DEPRECATED. Currently set to the same as remoteAddress. An extension that relies on this value must perform the remote lookup by itself.
     * @param cert
     *            X509Certificate the caller asked for in the OCSP request
     * @param status
     *            CertificateStatus the status the certificate has according to the OCSP responder, null means the cert is good
     * @return Hashtable with X509Extensions <String oid, X509Extension ext> that will be added to responseExtensions by OCSP responder, or null if an
     *         error occurs
     * @throws IOException 
     */
    Map<ASN1ObjectIdentifier, Extension> process(X509Certificate[] requestCertificates, String remoteAddress, String remoteHost,
            X509Certificate cert, CertificateStatus status);

    /**
     * Returns the last error that occured during process(), when process returns null
     * 
     * @return error code as defined by implementing class
     */
    int getLastErrorCode();
}
