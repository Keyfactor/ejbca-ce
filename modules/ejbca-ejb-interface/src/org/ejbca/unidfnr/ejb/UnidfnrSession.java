/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.unidfnr.ejb;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.cesecore.certificates.certificate.request.RequestMessage;


/**
 * Interface for handling unid-fnr logic.
 * @version $Id$
 *
 */
public interface UnidfnrSession {
    
    static final String UNIDFNR_MODULE = "unidfnr-ejb";
    
    /**
     * Called when the data handling should be done.
     * @param req Request to be modified.
     * @param otherData some other data
     * @return the modified request
     * @throws HandlerException The handle may throw this exception if some error occurs. Throwing it prevents the certificate creation.
     */
    RequestMessage processUnidfnrRequestMessage(RequestMessage req, String otherData, String unidDataSource) throws HandlerException;
    
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
     * Exception thrown by handler. No certificate should be created if this exception is thrown.
     *
     */
    class HandlerException extends Exception {

        private static final long serialVersionUID = 1L;

        public HandlerException(String message) {
            super(message);
        }
    }

}
