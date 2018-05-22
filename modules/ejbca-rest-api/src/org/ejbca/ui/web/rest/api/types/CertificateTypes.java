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
package org.ejbca.ui.web.rest.api.types;

import java.util.List;

/**
 * A class representing general information about certificate.
 *
 * @version $Id: CertificateTypes.java 28909 2018-05-10 12:16:53Z tarmo_r_helmes $
 */
public class CertificateTypes {
    private List<CertificateResponse> certificates;

    public CertificateTypes(List<CertificateResponse> certificates) {
        this.certificates = certificates;
    }

    public List<CertificateResponse> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<CertificateResponse> certificates) {
        this.certificates = certificates;
    }
}
