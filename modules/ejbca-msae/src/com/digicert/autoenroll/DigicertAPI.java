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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.ejbca.msae.EnrollmentException;

import java.io.IOException;
import java.io.InputStream;

/**
 * The Class DigicertAPI.
 */
public class DigicertAPI {
    private static final Logger log = Logger.getLogger(DigicertAPI.class);
    private String apiKey;
    private String BASEURL = "https://www.digicert.com/services/v2";
    private final static String DEVAPIKEY_HEADER = "X-DC-DEVKEY";

    public DigicertAPI(String apiKey, String baseURL) {
        this.apiKey = apiKey;
        this.BASEURL = baseURL;
    }

    /**
     * **********************************
     * Submitting Orders *
	 * *********************************
     */
    public HttpEntity viewProductList() throws IOException, EnrollmentException {
        final String url = BASEURL + "/product";
        HttpResponse response = doGet(url);
        return response.getEntity();
    }

    public String viewProductDetails(String name_id) throws IOException, EnrollmentException {
        String url = BASEURL + "/product/" + name_id;
        HttpResponse response = doGet(url);
        HttpEntity entity = response.getEntity();
        return getStringContentFromEntity(entity);
    }

    String orderCertificate(String uri, JsonObject jsonObject) throws EnrollmentException, IOException {
        final String url = BASEURL + uri;
        HttpResponse response = doPost(url, jsonObject);
        HttpEntity entity = getEntityFromResponse(response, "POST");
        return getStringContentFromEntity(entity);
    }

    /**
     * **********************************
     * Request Management *
	 * *********************************
     */
    public HttpEntity listRequests() throws IOException, EnrollmentException {
        final String url = BASEURL + "/request";
        HttpResponse response = doGet(url);
        return response.getEntity();
    }

    public HttpEntity listRequests(String status) throws IOException, EnrollmentException {
        final String url = BASEURL + "/request" + "?" + status;
        HttpResponse response = doGet(url);
        return response.getEntity();
    }

    /**
     * **********************************
     * Order Management *
	 * *********************************
     */
    private HttpEntity viewCertificateOrder(int order_id) throws IOException, EnrollmentException {
        final String url = BASEURL + "/order/certificate/" + String.valueOf(order_id);
        HttpResponse response = doGet(url);
        return response.getEntity();
    }
    
    int getCertificateIdfromOrderId(int order_id) throws IOException, EnrollmentException {
        final HttpEntity entity = viewCertificateOrder(order_id);
        final String certificateOrder = getStringContentFromEntity(entity);

        final JsonObject certificateOrderObj = new JsonParser().parse(certificateOrder).getAsJsonObject();
        final JsonElement certificate = certificateOrderObj.get("certificate").getAsJsonObject();
        final JsonObject certificateObj = certificate.getAsJsonObject();

        return certificateObj.get("id").getAsInt();
    }
    
    public HttpEntity listCertificateOrders() throws IOException, EnrollmentException {
        final String url = BASEURL + "/order/certificate";
        HttpResponse response = doGet(url);
        return response.getEntity();
    }

    public HttpEntity listEmailValidations(int order_id) throws IOException, EnrollmentException {
        String uris = "/order/certificate/" + String.valueOf(order_id) + "/email-validation";
        String url = BASEURL + uris;

        HttpResponse response = doGet(url);
        return response.getEntity();
    }

    /**
     * **********************************
     * Certificate Management *
	 * *********************************
     */
    InputStream downloadClientCertificate(int certificate_id) throws IOException, EnrollmentException {
        final String url = BASEURL + "/certificate/" + String.valueOf(certificate_id) + "/download/format/p7b";

        final HttpResponse response = doGet(url, "*/*");
        final HttpEntity entity = response.getEntity();
        return entity.getContent();
    }

    InputStream downloadClientCertificateByFormat(int certificate_id, String format_type) throws IOException, EnrollmentException {
        final String url = BASEURL + "/certificate/" + String.valueOf(certificate_id) + "/download/format/" + format_type;

        final HttpResponse response = doGet(url, "*/*");
        final HttpEntity entity = response.getEntity();
        return entity.getContent();
    }

    private HttpEntity getEntityFromResponse(HttpResponse response, String requestType) throws EnrollmentException, IOException {
        final StatusLine statusLine = response.getStatusLine();
        final int statusCode = statusLine.getStatusCode();

        if(requestType.equals("POST")) {
            // Failed POST request, did not get status code 201
            if (statusCode != 201) {
                HttpEntity entity = response.getEntity();
                final String error_message = getStringContentFromEntity(entity);
                log.error("POST Error: " + error_message);

                throw new EnrollmentException("Failed : HTTP error code : " + statusCode + ":"
                        + statusLine.getReasonPhrase() + " : " + error_message);
            }
        }
        if(requestType.equals("GET")) {
            // Failed GET request, did not get status code 200
            if (statusCode != 200) {
                HttpEntity entity = response.getEntity();
                final String error_message = getStringContentFromEntity(entity);
                log.error("GET Error: " + error_message);

                throw new EnrollmentException("Failed : HTTP error code : " + statusCode + ":"
                        + statusLine.getReasonPhrase() + " : " + error_message);
            }
        }
        return response.getEntity();
    }

    private String getStringContentFromEntity(HttpEntity entity) throws IOException, EnrollmentException {
        try {
            final String content = EntityUtils.toString(entity);
            EntityUtils.consume(entity);
            return content;
        } catch (IOException e) {
            throw new EnrollmentException("Could not get string content from API response.");
        }
    }

    HttpResponse doGet(String url) throws IOException, EnrollmentException {
        HttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(url);
        httpGet.addHeader(DEVAPIKEY_HEADER, apiKey);
        httpGet.addHeader(HttpHeaders.ACCEPT, "application/json");
        return httpClient.execute(httpGet);
    }

    HttpResponse doGet(String url, String accept) throws EnrollmentException, IOException {
        HttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(url);
        httpGet.addHeader(DEVAPIKEY_HEADER, apiKey);
        httpGet.addHeader(HttpHeaders.ACCEPT, accept);
        return httpClient.execute(httpGet);
    }

    HttpResponse doPost(String url, JsonObject jsonObject) throws EnrollmentException, IOException {
        HttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(url);
        httpPost.addHeader(DEVAPIKEY_HEADER, apiKey);
        httpPost.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        StringEntity params = new StringEntity(jsonObject.toString());
        httpPost.setEntity(params);
        return httpClient.execute(httpPost);
    }
}
