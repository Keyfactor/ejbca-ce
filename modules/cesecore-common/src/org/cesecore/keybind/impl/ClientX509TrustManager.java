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
package org.cesecore.keybind.impl;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.X509TrustManager;

import org.cesecore.util.CertTools;

/**
 * 
 * @version $Id$
 */
public class ClientX509TrustManager implements X509TrustManager {

    private final Collection<Certificate> trustedCertificates = new ArrayList<Certificate>();
    
    public ClientX509TrustManager(final List<X509Certificate> trustedCertificates) {
        if (trustedCertificates!=null) {
            for (X509Certificate current : trustedCertificates) {
                this.trustedCertificates.add(current);
            }
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // TODO Improve
        try {
            CertTools.verify(chain[0], trustedCertificates);
        } catch (Exception e) {
            throw new CertificateException(e);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // TODO Improve
        try {
            CertTools.verify(chain[0], trustedCertificates);
        } catch (Exception e) {
            throw new CertificateException(e);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return trustedCertificates.toArray(new X509Certificate[0]);
    }

}
