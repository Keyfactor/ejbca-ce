/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.response;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

/**
 * A class representing general information about certificate.
 *
 * @version $Id: CertificatesRestResponse.java 28909 2018-05-10 12:16:53Z tarmo_r_helmes $
 */
public class CertificatesRestResponse {
    private List<CertificateRestResponse> certificates;

    public CertificatesRestResponse(List<CertificateRestResponse> certificates) {
        this.certificates = certificates;
    }

    public List<CertificateRestResponse> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<CertificateRestResponse> certificates) {
        this.certificates = certificates;
    }


    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static CertificatesRestResponseConverter converter() {
        return new CertificatesRestResponseConverter();
    }

    public static class CertificatesRestResponseConverter {

        public List<CertificateRestResponse> toRestResponses(final List<Certificate> certificateList) throws CertificateEncodingException {
            final List<CertificateRestResponse> certificateRestResponses = new ArrayList<>();
            if (certificateList != null) {
                for (final Certificate certificate : certificateList) {
                    certificateRestResponses.add(CertificateRestResponse.converter().toRestResponse(certificate));
                }
            }
            return certificateRestResponses;
        }
    }
}
