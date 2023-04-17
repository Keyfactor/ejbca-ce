/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons - Proprietary Modules:                             *
 *                                                                       *
 *  Copyright (c), Keyfactor Inc. All rights reserved.                   *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.commons.p11ng;

import java.security.cert.Certificate;

/**
 * Holder for the response data and certificate to simplify migration of the
 * unit tests that was designed for the old API.
 *
 */
public class SimplifiedResponse {
    private final byte[] processedData;
    private final Certificate signerCertificate;

    public SimplifiedResponse(byte[] processedData, Certificate signerCertificate) {
        this.processedData = processedData;
        this.signerCertificate = signerCertificate;
    }

    public byte[] getProcessedData() {
        return processedData;
    }

    public Certificate getSignerCertificate() {
        return signerCertificate;
    }
    
}
