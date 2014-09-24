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
package org.ejbca.core.model.ca.publisher;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;

/**
 * Publishers that implements this interface can support publishing of raw database objects,
 * including rowProtection.
 * 
 * @version $Id$
 */
public interface FullEntityPublisher {

    /**
     * Publishes a CertificateData object in order to retain rowversion and  integrity protection data. Any publisher overriding this method must also override the getPublisherVersion
     * method and return a value > 1 from there. 
     * 
     * @param authenticationToken an authentication token
     * @param certificateData a complete CertificateData object
     * @param base64CertData a complete Base64CertData object
     * 
     * @return true if storage was successful.
     * 
     * @throws PublisherException if a communication or other error occurs.
     */
    boolean storeCertificate(final AuthenticationToken authenticationToken, final CertificateData certificateData, final Base64CertData base64CertData) throws PublisherException;

    /** @return true if this publisher supports publishing with the full database objects */
    boolean isFullEntityPublishingSupported();
}
