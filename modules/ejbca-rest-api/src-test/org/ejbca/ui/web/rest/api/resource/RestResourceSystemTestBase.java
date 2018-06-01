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
package org.ejbca.ui.web.rest.api.resource;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClients;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.core.executors.ApacheHttpClient4Executor;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * An intermediate class to support REST API system tests.
 *
 * @version $Id: RestResourceSystemTestBase.java 29080 2018-05-31 11:12:13Z andrey_s_helmes $
 */
public class RestResourceSystemTestBase {

    private static final HttpClient httpClient;

    // TODO Dynamic host instead of 'localhost'?
    // TODO Dynamic port instead of '8443'?
    // TODO Dynamic key store / password
    // TODO Dynamic trust store / password
    static {
        try {
            final String keyStoreBasePath = "C:/Programs/wildfly-10.1.0.Final/standalone/configuration/keystore/";
            final String keyStorePassword = "changeit";
            final String trustStorePassword = "changeit";
            final KeyStore keyStore = loadJksKeyStoreFromFile(keyStoreBasePath + "superadmin.jks", keyStorePassword);
            final KeyStore trustStore = loadJksKeyStoreFromFile(keyStoreBasePath + "truststore.jks", trustStorePassword);
            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
            final TrustManagerFactory tmFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmFactory.init(trustStore);
            final SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(keyManagerFactory.getKeyManagers(), tmFactory.getTrustManagers(), null);
            //
            httpClient = HttpClients.custom()
                    .setSSLContext(sslContext)
                    .setSSLHostnameVerifier(new NoopHostnameVerifier())
                    .build();
        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException | UnrecoverableKeyException | KeyManagementException e) {
            throw new RuntimeException("Cannot setup a HttpClient with SSL connection.", e);
        }
    }

    /**
     * Forms a REST API request denoted by URI.
     * <br/>
     * For example newRequest("/v1/ca") forms the request on URL "https://localhost:8443/ejbca/ejbca-rest-api/v1/ca".
     *
     * @param uriPath a part of URL to make request on.
     *
     * @return An instance of ClientRequest.
     *
     * @see org.jboss.resteasy.client.ClientRequest
     */
    protected ClientRequest newRequest(final String uriPath) {
        final ClientExecutor clientExecutor = new ApacheHttpClient4Executor(httpClient);
        return new ClientRequest("https://localhost:8443/ejbca/ejbca-rest-api" + uriPath, clientExecutor);
    }

    private static KeyStore loadJksKeyStoreFromFile(final String keyStoreFilePath, final String keyStorePassword) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        final File keyStoreFile = new File(keyStoreFilePath);
        if(!keyStoreFile.exists() || !keyStoreFile.canRead()) {
            throw new KeyStoreException("Cannot access KeyStore file [" + keyStoreFilePath + "]");
        }
        final FileInputStream fis = new FileInputStream(keyStoreFile);
        keyStore.load(fis, keyStorePassword.toCharArray());
        fis.close();
        return keyStore;
    }

}
