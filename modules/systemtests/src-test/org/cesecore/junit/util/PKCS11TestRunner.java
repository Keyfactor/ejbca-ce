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

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collection;

import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;

/**
 * @version $Id$
 *
 */
public class PKCS11TestRunner extends CryptoTokenRunner {

    
    private static final String DEFAULT_TOKEN_PIN = "userpin1";
    private static final String ALIAS = "signKeyAlias åäöÅÄÖnâćŋA©Ba";

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateCreateSessionRemote.class);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            PKCS11TestRunner.class.getSimpleName()));

    public PKCS11TestRunner(Class<?> klass) throws Exception {
        super(klass);
    }

    public X509CA createX509Ca() throws Exception {
        X509CA x509ca = CaTestUtils.createTestX509CAOptionalGenKeys(getSubjectDn(), SystemTestsConfiguration.getPkcs11SlotPin(DEFAULT_TOKEN_PIN), false,
                true, "1024", X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        CAToken caToken = x509ca.getCAToken();
        caToken.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, ALIAS);
        caToken.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, ALIAS);
        x509ca.setCAToken(caToken);
        caSession.addCA(alwaysAllowToken, x509ca);
        int cryptoTokenId = caToken.getCryptoTokenId();
        cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, ALIAS, "1024");
        CAInfo info = caSession.getCAInfo(alwaysAllowToken, x509ca.getCAId());
        // We need the CA public key, since we activated the newly generated key, we know that it has a key purpose now
        PublicKey pk = cryptoTokenManagementSession.getPublicKey(alwaysAllowToken, cryptoTokenId, ALIAS).getPublicKey();
        EndEntityInformation user = new EndEntityInformation(super.getName(), info.getSubjectDN(), x509ca.getCAId(), null, null, new EndEntityType(
                EndEntityTypes.ENDUSER), 0, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        user.setPassword("foo123");
        SimpleRequestMessage req = new SimpleRequestMessage(pk, user.getUsername(), user.getPassword());
        CertificateResponseMessage response = certificateCreateSession.createCertificate(alwaysAllowToken, user, req,
                org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
        Collection<Certificate> certs = info.getCertificateChain();
        certs.add(response.getCertificate());
        info.setCertificateChain(certs);
        caSession.editCA(alwaysAllowToken, info);
        casToRemove.put(x509ca.getCAId(), x509ca);
        return x509ca;
    }

    @Override
    public void tearDownCa(CA ca) {
        int cryptoTokenId = ca.getCAToken().getCryptoTokenId();

        try {
            try {
                final String signKeyAlias = ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
                if (cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, signKeyAlias)) {
                    cryptoTokenManagementSession.removeKeyPair(alwaysAllowToken, cryptoTokenId, signKeyAlias);
                }
            } catch (InvalidKeyException e) {
                throw new IllegalStateException(e);
            } catch (CryptoTokenOfflineException e) {
                throw new IllegalStateException(e);
            }
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId);
            if (ca != null) {
                CAInfo caInfo;
                try {
                    caInfo = caSession.getCAInfo(alwaysAllowToken, ca.getCAId());
                    final int caCryptoTokenId = caInfo.getCAToken().getCryptoTokenId();
                    cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, caCryptoTokenId);
                    caSession.removeCA(alwaysAllowToken, ca.getCAId());
                } catch (CADoesntExistsException e) {
                    // NOPMD Ignore
                }
            }
            internalCertificateStoreSession.removeCertificatesBySubject(getSubjectDn());
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        }
        casToRemove.remove(ca.getCAId());
    }

    @Override
    public String getSubtype() {
        return "pkcs11";
    }

    @Override
    public Integer createCryptoToken() throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException,
            NoSuchSlotException {
        try {
            cryptoTokenId = CryptoTokenTestUtils.createPKCS11Token(alwaysAllowToken, super.getName(), true);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Always Allow token was denied access.", e);
        }
        return cryptoTokenId;
    }

}
