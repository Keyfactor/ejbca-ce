/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package com.digicert.autoenroll;

import com.google.gson.JsonObject;

import org.apache.log4j.Logger;
import org.ejbca.msae.ADObject;
import org.ejbca.msae.ASN1;
import org.ejbca.msae.EnrollmentException;
import org.ejbca.msae.TemplateSettings;

import java.io.IOException;
import java.util.HashMap;

public class DigicertRequest {
    private static final Logger log = Logger.getLogger(DigicertRequest.class);
    private JsonObject jsonRequest;
    private String product;

    public DigicertRequest(TemplateSettings templateSettings, ADObject adObject, String domain, String pkcs10request,
                           String msTemplateHexValue) throws IOException, EnrollmentException {
        setJsonRequest(templateSettings, adObject, domain, pkcs10request, msTemplateHexValue);
        this.product = templateSettings.getProduct();
    }

    public byte[] certificateRequest(DigicertCA digicertCA) throws EnrollmentException {
        return digicertCA.issuePKCS7Certificate(jsonRequest, product);
    }

    private void setJsonRequest(TemplateSettings templateSettings, ADObject adObject, String domain, String pkcs10request,
                        String msTemplateHexValue) throws EnrollmentException, IOException {
        final HashMap<String, String> msTemplateValues = ASN1.msTemplateValueToASN1Strings(msTemplateHexValue);

        JsonRequest params = new JsonRequest(templateSettings, adObject, domain, pkcs10request, msTemplateValues);
        jsonRequest = params.createJsonRequest();

        if (log.isDebugEnabled()) {
            log.debug(jsonRequest.toString());
        }
    }
}
