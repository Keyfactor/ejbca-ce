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
package org.cesecore.junit.util;

import java.security.cert.X509Certificate;
import java.util.Date;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.KeyGenParams;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.runners.model.InitializationError;

/**
 * @version $Id$
 *
 */
public class PKCS12TestRunner extends CryptoTokenRunner {
    
    private static final String ALIAS = "signKeyAlias";
    
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            PKCS12TestRunner.class.getSimpleName()));

 
    public PKCS12TestRunner(Class<?> klass) throws InitializationError, NoSuchMethodException, SecurityException {
        super(klass);
    }

    @Override
    public X509CA createX509Ca() throws Exception {
        X509CA x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(alwaysAllowToken, getSubjectDn());
        int cryptoTokenId = x509ca.getCAToken().getCryptoTokenId();
        cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, ALIAS, KeyGenParams.builder("RSA1024").build());      
        X509Certificate caCertificate = (X509Certificate) x509ca.getCACertificate();
        //Store the CA Certificate.
        certificateStoreSession.storeCertificateRemote(alwaysAllowToken, EJBTools.wrap(caCertificate), "foo", "1234", CertificateConstants.CERT_ACTIVE,
                CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, EndEntityConstants.NO_END_ENTITY_PROFILE,
                CertificateConstants.NO_CRL_PARTITION, "footag", new Date().getTime());
        casToRemove.put(x509ca.getCAId(), x509ca);
        return x509ca;
    }
    
    @Override
    public void tearDownCa(CA ca) {
        if (ca != null) {
            int cryptoTokenId = ca.getCAToken().getCryptoTokenId();
            try {
                cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId);
                CAInfo caInfo = caSession.getCAInfo(alwaysAllowToken, ca.getCAId());
                if (caInfo != null) {
                    final int caCryptoTokenId = caInfo.getCAToken().getCryptoTokenId();
                    cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, caCryptoTokenId);
                    caSession.removeCA(alwaysAllowToken, ca.getCAId());
                }
            } catch (AuthorizationDeniedException e) {
                throw new IllegalStateException(e);
            } 
        }
        internalCertificateStoreSession.removeCertificatesBySubject(getSubjectDn());
        casToRemove.remove(ca.getCAId());
    }
    

    @Override
    public String getSubtype() {       
        return "pkcs12";
    }

    @Override
    public Integer createCryptoToken() throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException,
             NoSuchSlotException {
        try {
            cryptoTokenId = CryptoTokenTestUtils.createSoftCryptoToken(alwaysAllowToken, super.getName());
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Always Allow token was denied access.", e);
        }
        return cryptoTokenId;
    }

}
