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
package org.cesecore.certificates.certificate;

import java.io.Serializable;
import java.security.cert.Certificate;

/**
 * Richer version of the standard CertificateStatus object which also contains the sought certificate, in order to avoid
 * extra database lookups when both are required. 
 * 
 * @version $Id$
 *
 */
public class CertificateStatusHolder implements Serializable {

    private static final long serialVersionUID = -2881054831054645112L;
    private final Certificate certificate;
    private final CertificateStatus certificateStatus;
    
    public CertificateStatusHolder(Certificate certificate, CertificateStatus certificateStatus) {
        this.certificate = certificate;
        this.certificateStatus = certificateStatus;
    }

    /**
     * 
     * @return the sought certificate. May be null if status was unknown.
     */
    public Certificate getCertificate() {
        return certificate;
    }

    public CertificateStatus getCertificateStatus() {
        return certificateStatus;
    }

}
