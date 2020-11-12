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

import org.apache.log4j.Logger;
import org.ejbca.msae.ApplicationProperties;
import org.ejbca.msae.CertUtils;
import org.ejbca.msae.EnrollmentException;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.InputStream;

public class DigicertCA {

    private static final Logger log = Logger.getLogger(DigicertCA.class);

    private DigicertAPI api;

    public DigicertCA(ApplicationProperties msEnrollmentProperties) {
        this.api = new DigicertAPI(msEnrollmentProperties.getAPIKEY(), msEnrollmentProperties.getBASEURL());
    }

    private String orderCertificate(JsonObject jsonRequest, String product) throws Exception {
        EndpointFactory endpoint = new EndpointFactory();
        return api.orderCertificate(endpoint.makeOrderEndpoint(product), jsonRequest);
    }

    private int getOrderIdFromJsonResponse(String responseJson) {
        JsonObject responseObj = new JsonParser().parse(responseJson).getAsJsonObject();
        int order_id = responseObj.get("id").getAsInt();
        log.info("Got Order ID [ " + order_id + " ] from API Response.");
        return order_id;
    }

    private int getCertificateIdfromOrderId(int order_id) throws IOException, EnrollmentException {
        int certificate_id = api.getCertificateIdfromOrderId(order_id);
        log.info("Got Certificate ID [ " + certificate_id + " ] from Order ID [ " + order_id + " ]");
        return certificate_id;
    }

    private InputStream downloadCertificate(int certificate_id) throws IOException, EnrollmentException {
        return api.downloadClientCertificate(certificate_id);
    }

    public byte[] issuePKCS7Certificate(JsonObject jsonRequest, String product) throws EnrollmentException {
        InputStream is = null;
        byte[] certificate;
        try {
            String responseJson = orderCertificate(jsonRequest, product);
            int order_id = getOrderIdFromJsonResponse(responseJson);
            int certificate_id = getCertificateIdfromOrderId(order_id);
            log.info("Downloading Certificate using Certificate ID: " + certificate_id);
            is = downloadCertificate(certificate_id);
            //Collection<X509CertificateHolder> collection = CertUtils.parseP7B(is);
            certificate = CertUtils.getPKCS7Certificate(is);
        } catch (Exception e) {
            throw new EnrollmentException("Could not generate certificate: " + e.getMessage());
        } finally {
            if(is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    log.error("IOException: ", e);
                }
            }
        }
        return certificate;
    }
}