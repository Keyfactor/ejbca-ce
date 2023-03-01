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
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;


/**
 * Base class for crypto token variations of the test runner. 
 * 
 *
 */
public abstract class CryptoTokenRunner {

    public static final List<CryptoTokenRunner> defaultRunners =  Arrays.asList(new PKCS12TestRunner(), new PKCS11TestRunner(), new P11NGTestRunner());
    
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    
    private final CryptoTokenSessionRemote cryptoTokenSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenSessionRemote.class);

    private Map<Integer, X509CAInfo> casToRemove = new HashMap<>();
    private Set<Integer> cryptoTokenstoRemove = new HashSet<>();

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            CryptoTokenRunner.class.getSimpleName()));

    
    public void setCryptoTokenForRemoval(int cryptoTokenId) {
        cryptoTokenstoRemove.add(cryptoTokenId);
    }
    
    public void setCaForRemoval(int caId, X509CAInfo x509caInfo) {
        casToRemove.put(caId, x509caInfo);
    }
    
    public CryptoTokenRunner() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    public void tearDownAllCas() {
        List<X509CAInfo> defensiveCopy = new ArrayList<>(casToRemove.values());
        for(X509CAInfo ca : defensiveCopy) {
            tearDownCa(ca);
        }
    }

    public void teardownCryptoToken() {
        try {
            for (int cryptoTokenId : cryptoTokenstoRemove) {                
                if (cryptoTokenManagementSession.isCryptoTokenPresent(alwaysAllowToken, cryptoTokenId)) {
                    try {
                        for (KeyPairInfo keyPairInfo : cryptoTokenManagementSession.getKeyPairInfos(alwaysAllowToken, cryptoTokenId)) {
                            cryptoTokenManagementSession.removeKeyPair(alwaysAllowToken, cryptoTokenId, keyPairInfo.getAlias());
                        }
                    } catch (InvalidKeyException | CryptoTokenOfflineException e) {
                        throw new IllegalStateException(e);
                    }
                }
                
                cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId);
            }
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        }
    }

    public abstract String getSimpleName();

    
    public abstract X509CAInfo createX509Ca(String subjectDn, String username) throws Exception;

    public void tearDownCa(X509CAInfo ca) {
        final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        
        int cryptoTokenId = ca.getCAToken().getCryptoTokenId();

        try {
            CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
            if (cryptoToken != null) {
                try {
                    for (KeyPairInfo keyPairInfo : cryptoTokenManagementSession.getKeyPairInfos(alwaysAllowToken, cryptoTokenId)) {
                        cryptoTokenManagementSession.removeKeyPair(alwaysAllowToken, cryptoTokenId, keyPairInfo.getAlias());
                    }
                } catch (InvalidKeyException | CryptoTokenOfflineException e) {
                    throw new IllegalStateException(e);
                }
            }
            
            
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId);
            if (ca != null) {
                caSession.removeCA(alwaysAllowToken, ca.getCAId());
            }
            Certificate caCertificate = ca.getCertificateChain().get(0);
            if (caCertificate != null) {
                internalCertificateStoreSession.removeCertificate(caCertificate);
            }
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        }
        casToRemove.remove(ca.getCAId());
    }

    /**
     * @return a string differentiatior for the class inheriting this baseclass, mostly used for naming reasons. 
     */
    public abstract String getNamingSuffix();
    
    /**
     * Will create a crypto token, as defined by the implementing subclass. 
     * 
     * @param tokenName the name of the token
     * 
     * @return the crypto token ID, never null.
     * @throws NoSuchSlotException if the defined slot could not be found
     * @throws CryptoTokenNameInUseException if a crypto token with the predefined name already exists
     * @throws CryptoTokenAuthenticationFailedException if the crypto token could not be authenticated against
     * @throws CryptoTokenOfflineException if the crypto token could not be activated
     */
    public abstract Integer createCryptoToken(final String tokenName) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, NoSuchSlotException;
    
    /**
     * 
     * @return true if this runner can be run in the current environment. 
     */
    public abstract boolean canRun();
    
    public void cleanUp() {
        teardownCryptoToken();
        tearDownAllCas();
    }
    
    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    protected X509CAInfo createTestX509Ca(final String caName, String cadn, char[] tokenpin, boolean genKeys, String cryptoTokenImplementation, int signedBy, final String keyspec,
            int keyusage) throws CryptoTokenOfflineException, CertificateParsingException, OperatorCreationException {
        final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("createTestX509CAOptionalGenKeys"));

        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        
        final String signingKeyName = caName + "_" + CAToken.SOFTPRIVATESIGNKEYALIAS;
        final String encryptionKeyName = caName + "_" + CAToken.SOFTPRIVATEDECKEYALIAS;
        
        cryptoTokenManagementProxySession.flushCache();
        int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(alwaysAllowToken, tokenpin, genKeys, cryptoTokenImplementation, cadn, keyspec, keyspec, signingKeyName, encryptionKeyName);
        cryptoTokenstoRemove.add(cryptoTokenId);
        try {
            cryptoTokenManagementSession.activate(alwaysAllowToken, cryptoTokenId, tokenpin);
        } catch (CryptoTokenOfflineException | CryptoTokenAuthenticationFailedException | AuthorizationDeniedException e) {
            throw new IllegalStateException("Could not activate crypto token", e);
        }
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, signingKeyName, encryptionKeyName);
        final List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<>(2);
        extendedCaServices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        String caname = CertTools.getPartFromDN(cadn, "CN");
        boolean ldapOrder = !CertTools.isDNReversed(cadn);
        int certificateProfileId = (signedBy == CAInfo.SELFSIGNED ? CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA : CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(cadn, caname, CAConstants.CA_ACTIVE, certificateProfileId, "3650d",
                signedBy, null, catoken);
        cainfo.setDescription(caName);
        cainfo.setExtendedCAServiceInfos(extendedCaServices);
        cainfo.setUseLdapDnOrder(ldapOrder);
        cainfo.setCmpRaAuthSecret("foo123");
        cainfo.setDeltaCRLPeriod(10 * SimpleTime.MILLISECONDS_PER_HOUR); // In order to be able to create deltaCRLs
        cainfo.setDoEnforceUniqueDistinguishedName(true);
        cainfo.setDoEnforceUniquePublicKeys(true);
        cryptoTokenManagementProxySession.flushCache();
        
        final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        try {
            caAdminSession.createCA(alwaysAllowToken, cainfo);
        } catch (CAExistsException | CryptoTokenOfflineException | InvalidAlgorithmException | AuthorizationDeniedException e) {
            cleanUp();
            throw new IllegalStateException(e);
        }
        try {
            return (X509CAInfo) caSession.getCAInfo(alwaysAllowToken, cainfo.getCAId());
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        }
    }
    
    protected int createCryptoToken(final char[] pin, final String cryptTokenImplementation, final String tokenName) {
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        
        int cryptoTokenId = CryptoTokenTestUtils.createCryptoToken(pin, cryptTokenImplementation, tokenName);
        cryptoTokenstoRemove.add(cryptoTokenId);
        try {
            cryptoTokenManagementSession.activate(alwaysAllowToken, cryptoTokenId, pin);
        } catch (CryptoTokenOfflineException | CryptoTokenAuthenticationFailedException | AuthorizationDeniedException e) {
            throw new IllegalStateException("Could not activate crypto token", e);
        }
        cryptoTokenManagementProxySession.flushCache();
        return cryptoTokenId;
    }
    
    
    protected abstract String getTokenImplementation();

}
