/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;

/**
 * Common class for test classes which need to create a CA.   
 * 
 * @version $Id$
 *
 */
public abstract class CaTestUtils {

    /**
     * Creates and stores a simple X509 CA 
     * 
     * @param authenticationToken
     * @param cryptoTokenName
     * @param cadn
     */
    public static CA createX509Ca(AuthenticationToken authenticationToken, String cryptoTokenName, String caName, String cadn)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException,
            AuthorizationDeniedException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, KeyStoreException, CertificateException, InvalidAlgorithmException, IllegalStateException, OperatorCreationException,
            IOException, CAExistsException, IllegalCryptoTokenException {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo123");
        int cryptoTokenId;
        if (!cryptoTokenManagementProxySession.isCryptoTokenNameUsed(cryptoTokenName)) {
            cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, cryptoTokenName, SoftCryptoToken.class.getName(),
                    cryptoTokenProperties, null, null);
        } else {
            cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        }
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS)) {
            cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS, "1024");
        }
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS)) {
            cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS, "1024");
        }

        final CryptoToken cryptoToken = cryptoTokenManagementProxySession.getCryptoToken(cryptoTokenId);
        final CA x509Ca = createX509Ca(cryptoToken, caName, cadn);
        caSession.addCA(authenticationToken, x509Ca);
        return x509Ca;
    }

    
    private static CA createX509Ca(final CryptoToken cryptoToken, String caName, String cadn) throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, KeyStoreException, CertificateException,
            CryptoTokenOfflineException, IOException, InvalidAlgorithmException, IllegalStateException, OperatorCreationException {
        Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
        // Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
        catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // No extended services
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        X509CAInfo cainfo = new X509CAInfo(cadn, caName, CAConstants.CA_ACTIVE, new Date(), "", CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA,
                3650, null, // Expiretime
                CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, (Collection<Certificate>) null, catoken, "JUnit RSA CA", -1, null, null, // PolicyId
                24 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLPeriod
                0 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLIssueInterval
                10 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLOverlapTime
                10 * SimpleTime.MILLISECONDS_PER_HOUR, // DeltaCRLPeriod
                new ArrayList<Integer>(), true, // Authority Key Identifier
                false, // Authority Key Identifier Critical
                true, // CRL Number
                false, // CRL Number Critical
                null, // defaultcrldistpoint
                null, // defaultcrlissuer
                null, // defaultocsplocator
                null, // Authority Information Access
                null, // defaultfreshestcrl
                true, // Finish User
                extendedcaservices, false, // use default utf8 settings
                new ArrayList<Integer>(), // Approvals Settings
                1, // Number of Req approvals
                false, // Use UTF8 subject DN by default
                true, // Use LDAP DN order by default
                false, // Use CRL Distribution Point on CRL
                false, // CRL Distribution Point on CRL critical
                true, true, // isDoEnforceUniquePublicKeys
                true, // isDoEnforceUniqueDistinguishedName
                false, // isDoEnforceUniqueSubjectDNSerialnumber
                false, // useCertReqHistory
                true, // useUserStorage
                true, // useCertificateStorage
                null // cmpRaAuthSecret
        );
        X509CA x509ca = new X509CA(cainfo);
        x509ca.setCAToken(catoken);
        // A CA certificate
        X509Certificate cacert = CertTools.genSelfCert(cadn, 10L, "1.1.1.1",
                cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                "SHA256WithRSA", true);
        assertNotNull(cacert);
        Collection<Certificate> cachain = new ArrayList<Certificate>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);
        // Now our CA should be operational
        return x509ca;
    }
    
    public static void removeCA(AuthenticationToken authenticationToken, String cryptoTokenName, String caName) throws AuthorizationDeniedException, CADoesntExistsException {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        int caid = caSession.getCAInfo(authenticationToken, caName).getCAId();
        caSession.removeCA(authenticationToken, caid);
        int cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
    }
}
