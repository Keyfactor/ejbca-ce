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
import java.util.Iterator;

import javax.net.ssl.X509TrustManager;

import org.cesecore.util.CertTools;

/**
 * 
 * @version $Id$
 */
public class ClientX509TrustManager implements X509TrustManager {

    private Collection<Collection<Certificate> > trustedCertificatesChains = null;
    
    public ClientX509TrustManager(final Collection< Collection<Certificate> > trustedCertificates) {
        if (trustedCertificates!=null) {
            trustedCertificatesChains = new ArrayList<Collection<Certificate> >();
            for(Collection<Certificate> col : trustedCertificates) {
                this.trustedCertificatesChains.add(col);
            }
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        X509Certificate cert = chain[0];
        if(!CertTools.verifyWithTrustedCertificates(cert, trustedCertificatesChains)) {
            String subjectdn = CertTools.getSubjectDN(cert);
            String issuerdn = CertTools.getIssuerDN(cert);
            String sn = CertTools.getSerialNumberAsString(cert);
            String errmsg = "Certificate with SubjectDN '" + subjectdn + "', IssuerDN '" + issuerdn + 
                    "' and serialnumber '" + sn + "' is NOT trusted.";
            throw new CertificateException(errmsg);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        X509Certificate cert = chain[0];
        if(!CertTools.verifyWithTrustedCertificates(cert, trustedCertificatesChains)) {
            String subjectdn = CertTools.getSubjectDN(cert);
            String issuerdn = CertTools.getIssuerDN(cert);
            String sn = CertTools.getSerialNumberAsString(cert);
            String errmsg = "Certificate with SubjectDN '" + subjectdn + "', IssuerDN '" + issuerdn + 
                    "' and serialnumber '" + sn + "' is NOT trusted.";
            throw new CertificateException(errmsg);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        if(trustedCertificatesChains == null) {
            return new X509Certificate[0];
        }
        
        ArrayList<X509Certificate> acceptedIssuers = new ArrayList<X509Certificate>();
        for(Collection<Certificate> certChain : trustedCertificatesChains) {
            Iterator<Certificate> itr = certChain.iterator();
            X509Certificate cert = (X509Certificate) itr.next();
            if(CertTools.isCA(cert)) {
                acceptedIssuers.add(cert);
            } else {
                acceptedIssuers.add((X509Certificate) itr.next() );
            }
        }
        return acceptedIssuers.toArray(new X509Certificate[0]);
    }

}
