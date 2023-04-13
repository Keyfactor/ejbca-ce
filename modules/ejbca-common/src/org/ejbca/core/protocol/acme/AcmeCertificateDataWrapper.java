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
package org.ejbca.core.protocol.acme;

import java.util.ArrayList;
import java.util.List;

import org.cesecore.certificates.certificate.CertificateDataWrapper;

public class AcmeCertificateDataWrapper extends CertificateDataWrapper {

    private static final long serialVersionUID = 959555023085370857L;
    
    private List<String> alternateChainAliases;

    public AcmeCertificateDataWrapper(CertificateDataWrapper cdw) {
        super(cdw.getCertificateData(), cdw.getBase64CertData());
        alternateChainAliases = new ArrayList<>();
    }

    public List<String> getAlternateChainAliases() {
        return alternateChainAliases;
    }

    public void setAlternateChainAliases(List<String> alternateChainAliases) {
        this.alternateChainAliases = alternateChainAliases;
    }
}
