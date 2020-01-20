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
package org.cesecore.keybind.impl;

import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.cesecore.certificates.pinning.TrustEntry;
import org.cesecore.util.CertTools;
import org.cesecore.util.provider.EkuPKIXCertPathChecker;

/**
 * 
 * @version $Id$
 */
public class ClientX509TrustManager implements X509TrustManager {
    private final Logger log = Logger.getLogger(ClientX509TrustManager.class);
    private final List<TrustEntry> trustEntries;
    private List<X509Certificate> encounteredServerCertificateChain;
    
    public ClientX509TrustManager(final List<TrustEntry> trustEntries) {
        this.trustEntries = trustEntries;
    }

    @Override
    public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
        checkCertificate(chain[0], new EkuPKIXCertPathChecker(KeyPurposeId.id_kp_clientAuth.getId()));
    }

    @Override
    public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
        encounteredServerCertificateChain = new ArrayList<>(Arrays.asList(chain));
        checkCertificate(chain[0], new EkuPKIXCertPathChecker(KeyPurposeId.id_kp_serverAuth.getId()));
    }

    private void checkCertificate(final X509Certificate leafCertificate, final PKIXCertPathChecker pkixPathChecker)
            throws CertificateException {
        final List<Collection<X509Certificate>> trustedCertificateChains = getTrustedCertificateChains(leafCertificate);
        if (log.isDebugEnabled()) {
            if (trustedCertificateChains == null) {
                log.debug("Verifying the leaf certificate '" + CertTools.getSubjectDN(leafCertificate) + "' with no trusted certificate chains.");
            } else {
                log.debug("Verifying the leaf certificate '" + CertTools.getSubjectDN(leafCertificate) + "' with trusted certificate chains "
                        + trustedCertificateChains.stream()
                            .map(chain -> chain.stream().map(x -> CertTools.getSubjectDN(x)).collect(Collectors.toList()))
                            .collect(Collectors.toList()));
            }
        }
        if (!CertTools.verifyWithTrustedCertificates(leafCertificate, trustedCertificateChains, pkixPathChecker)) {
            String subjectdn = CertTools.getSubjectDN(leafCertificate);
            String issuerdn = CertTools.getIssuerDN(leafCertificate);
            String sn = CertTools.getSerialNumberAsString(leafCertificate);
            String errmsg = "Certificate with SubjectDN '" + subjectdn + "', IssuerDN '" + issuerdn + 
                    "' and serial number '" + sn + "' is NOT trusted.";
            throw new CertificateException(errmsg);
        }
    }

    private List<Collection<X509Certificate>> getTrustedCertificateChains(final X509Certificate leafCertificate) throws CertificateException {
        if (trustEntries.isEmpty()) {
            // Nothing configured in the internal key binding. Trust ANY CA known to this EJBCA instance
            return Collections.emptyList();
        }
        final List<Collection<X509Certificate>> trustedCertificateChains = trustEntries.stream()
                .map(trustEntry -> trustEntry.getChain(leafCertificate))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());
        return trustedCertificateChains.isEmpty() ? null : trustedCertificateChains;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return trustEntries.stream().map(trustEntry -> trustEntry.getIssuer()).toArray(X509Certificate[]::new);
    }

    /** @return the encountered server side certificate chain that this class has been asked to verify or null if none has been encountered yet. */
    public List<X509Certificate> getEncounteredServerCertificateChain() {
        return encounteredServerCertificateChain;
    }
}
