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
package org.ejbca.core.ejb.authentication;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.security.auth.x500.X500Principal;

import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.util.CertTools;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.JndiHelper;

/**
 *
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "WebAuthenticationProviderSessionLocal")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class WebAuthenticationProviderSessionBean implements WebAuthenticationProviderSessionLocal {

    private static final long serialVersionUID = 1524951666783567785L;

    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;

    @Override
    public AuthenticationToken authenticate(AuthenticationSubject subject) {

        X509Certificate[] certificateArray = subject.getCredentials().toArray(new X509Certificate[0]);
        if (certificateArray.length != 1) {
            return null;
        } else {
            X509Certificate certificate = certificateArray[0];
            // Check Validity
            try {
                certificate.checkValidity();
            } catch (Exception e) {
                return null;
            }
            if (WebConfiguration.getRequireAdminCertificateInDatabase()) {
                // TODO: Verify Signature on cert? Not really needed since it's one of our certs in the database.
                // Check if certificate is revoked.
                boolean isRevoked = certificateStoreSession.isRevoked(CertTools.getIssuerDN(certificate), CertTools.getSerialNumber(certificate));
                if (isRevoked) {
                    return null;
                }
            } else {
                // TODO: We should check the certificate for CRL or OCSP tags and verify the certificate status
            }
            final Set<X500Principal> principals = new HashSet<X500Principal>();
            principals.add(certificate.getSubjectX500Principal());
            final Set<X509Certificate> credentials = new HashSet<X509Certificate>();
            credentials.add(certificate);
            return new X509CertificateAuthenticationToken(principals, credentials);
        }

    }

}
