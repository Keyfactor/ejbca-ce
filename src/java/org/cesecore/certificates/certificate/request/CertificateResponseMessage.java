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
package org.cesecore.certificates.certificate.request;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * Interface extending ResponseMessage to add certificate functionality.
 * 
 * @version $Id$
 *
 */
public interface CertificateResponseMessage extends ResponseMessage {

    /**
     * Gets the complete certificate in the response message.
     *
     * @return certificate in the response message.
     * 
     * @throws CertificateException if the byte array in this response does not contain a proper certificate
     */
    Certificate getCertificate();
    
    /**
     * Sets the complete certificate in the response message.
     *
     * @param cert certificate in the response message.
     */
    void setCertificate(Certificate cert);
}
