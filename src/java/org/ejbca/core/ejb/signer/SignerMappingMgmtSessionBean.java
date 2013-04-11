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
package org.ejbca.core.ejb.signer;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;

/**
 * Generic Management implementation for SignerMappings.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "SignerMappingMgmtSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class SignerMappingMgmtSessionBean implements SignerMappingMgmtSessionLocal, SignerMappingMgmtSessionRemote {

    private static final Logger log = Logger.getLogger(SignerMappingDataSessionBean.class);
    private static final InternalResources intres = InternalResources.getInstance();

    @EJB
    private AccessControlSessionLocal accessControlSessionSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private SignerMappingDataSessionLocal signerMappingDataSession;
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getSignerMappingIds(AuthenticationToken authenticationToken, String signerMappingType) {
        final List<Integer> allIds = signerMappingDataSession.getSignerMappingIds(signerMappingType);
        final List<Integer> authorizedIds = new ArrayList<Integer>();
        for (final Integer current : allIds) {
            if (accessControlSessionSession.isAuthorizedNoLogging(authenticationToken, SignerMappingRules.VIEW.resource()+"/"+current.toString())) {
                authorizedIds.add(current);
            }
        }
        return authorizedIds;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public SignerMapping getSignerMapping(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.VIEW.resource()+"/"+signerMappingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.VIEW.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return signerMappingDataSession.getSignerMapping(signerMappingId);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Integer getIdFromName(String signerMappingName) {
        if (signerMappingName==null) {
            return null;
        }
        final Map<String, Integer> cachedNameToIdMap = signerMappingDataSession.getCachedNameToIdMap();
        Integer signerMappingId = cachedNameToIdMap.get(signerMappingName);
        if (signerMappingId == null) {
            // Ok.. so it's not in the cache.. look for it the hard way..
            for (final Integer currentId : signerMappingDataSession.getSignerMappingIds(null)) {
                // Don't lookup CryptoTokens we already have in the id to name cache
                if (!cachedNameToIdMap.keySet().contains(currentId)) {
                    final SignerMapping current = signerMappingDataSession.getSignerMapping(currentId.intValue());
                    final String currentName = current == null ? null : current.getName();
                    if (signerMappingName.equals(currentName)) {
                        signerMappingId = currentId;
                        break;
                    }
                }
            }
        }
        return signerMappingId;
    }

    @Override
    public int persistSignerMapping(AuthenticationToken authenticationToken, SignerMapping signerMapping)
            throws AuthorizationDeniedException, SignerMappingNameInUseException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.MODIFY.resource()+"/"+signerMapping.getId(),
                CryptoTokenRules.USE.resource()+"/"+signerMapping.getCryptoTokenId())) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return signerMappingDataSession.mergeSignerMapping(signerMapping);
    }

    @Override
    public boolean deleteSignerMapping(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.DELETE.resource() + "/" + signerMappingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.DELETE.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return signerMappingDataSession.removeSignerMapping(signerMappingId);
    }

    @Override
    public void generateNextKeyPair(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException,
            CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.MODIFY.resource() + "/" + signerMappingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final SignerMapping signerMapping = signerMappingDataSession.getSignerMapping(signerMappingId);
        final int cryptoTokenId = signerMapping.getCryptoTokenId();
        final String currentKeyPairAlias = signerMapping.getKeyPairAlias();
        signerMapping.generateNextKeyPairAlias();
        final String nextKeyPairAlias = signerMapping.getNextKeyPairAlias();
        cryptoTokenManagementSession.createKeyPairWithSameKeySpec(authenticationToken, cryptoTokenId, currentKeyPairAlias, nextKeyPairAlias);
        try {
            signerMappingDataSession.mergeSignerMapping(signerMapping);
        } catch (SignerMappingNameInUseException e) {
            // This would be very strange if it happened, since we use the same name and id as for the existing one
            throw new RuntimeException(e);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public byte[] getNextPublicKeyForSignerMapping(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.VIEW.resource() + "/" + signerMappingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.VIEW.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final SignerMapping signerMapping = signerMappingDataSession.getSignerMapping(signerMappingId);
        final int cryptoTokenId = signerMapping.getCryptoTokenId();
        final String nextKeyPairAlias = signerMapping.getNextKeyPairAlias();
        final String keyPairAlias;
        if (nextKeyPairAlias == null) {
            keyPairAlias = signerMapping.getKeyPairAlias();
        } else {
            keyPairAlias = nextKeyPairAlias;
        }
        final PublicKey publicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, keyPairAlias);
        return publicKey.getEncoded();
    }

    @Override
    public void updateCertificateForSignerMapping(AuthenticationToken authenticationToken, int signerMappingId)
            throws AuthorizationDeniedException, CertificateImportException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.MODIFY.resource() + "/" + signerMappingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final SignerMapping signerMapping = signerMappingDataSession.getSignerMapping(signerMappingId);
        final int cryptoTokenId = signerMapping.getCryptoTokenId();
        final String nextKeyPairAlias = signerMapping.getNextKeyPairAlias();
        boolean updated = false;
        if (nextKeyPairAlias == null) {
            // If a nextKeyPairAlias is present we assume that this is the one we want to find a certificate for
            PublicKey nextPublicKey;
            try {
                nextPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, nextKeyPairAlias);
            } catch (CryptoTokenOfflineException e) {
                throw new CertificateImportException("Operation is not available when CryptoToken is offline.", e);
            }
            if (nextPublicKey != null) {
                final byte[] subjectKeyId;
                try {
                    subjectKeyId = KeyTools.createSubjectKeyId(nextPublicKey).getEncoded();
                } catch (IOException e) {
                    throw new CertificateImportException(e);
                }
                final Certificate certificate = certificateStoreSession.findMostRecentlyUpdatedActiveCertificate(subjectKeyId);
                if (certificate != null) {
                    // Verify that this is an accepted type of certificate to import for the current implementation
                    assertCertificateIsOkToImport(certificate, signerMapping);
                    // If current key matches next public key -> import and update nextKey + signerMapping.certificateId
                    String fingerprint = CertTools.getFingerprintAsString(certificate);
                    if (!fingerprint.equals(signerMapping.getCertificateId())) {
                        signerMapping.updateCertificateIdAndCurrentKeyAlias(fingerprint);
                        updated = true;
                    } else {
                        log.debug("The latest available certificate was already in use.");
                    }
                }
            }
        }
        if (!updated) {
            // We failed to find a matching certificate for the next key, so we instead try to do the same for the current key pair
            final String currentKeyPairAlias = signerMapping.getKeyPairAlias();
            PublicKey currentPublicKey;
            try {
                currentPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, currentKeyPairAlias);
            } catch (CryptoTokenOfflineException e) {
                throw new CertificateImportException("Operation is not available when CryptoToken is offline.", e);
            }
            if (currentPublicKey != null) {
                final byte[] subjectKeyId;
                try {
                    subjectKeyId = KeyTools.createSubjectKeyId(currentPublicKey).getEncoded();
                } catch (IOException e) {
                    throw new CertificateImportException(e);
                }
                final Certificate certificate = certificateStoreSession.findMostRecentlyUpdatedActiveCertificate(subjectKeyId);
                if (certificate != null) {
                    // Verify that this is an accepted type of certificate to import for the current implementation
                    assertCertificateIsOkToImport(certificate, signerMapping);
                    String fingerprint = CertTools.getFingerprintAsString(certificate);
                    signerMapping.setCertificateId(fingerprint);
                    updated = true;
                }
            }
        }
        if (updated) {
            try {
                signerMappingDataSession.mergeSignerMapping(signerMapping);
            } catch (SignerMappingNameInUseException e) {
                // This would be very strange if it happened, since we use the same name and id as for the existing one
                throw new CertificateImportException(e);
            }
        } else {
            throw new CertificateImportException("No certificate matching the keys were found.");
        }
    }

    @Override
    public void importCertificateForSignerMapping(AuthenticationToken authenticationToken, int signerMappingId, byte[] derEncodedCertificate)
            throws AuthorizationDeniedException, CertificateImportException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.MODIFY.resource() + "/" + signerMappingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final SignerMapping signerMapping = signerMappingDataSession.getSignerMapping(signerMappingId);
        // UnDERify
        final Certificate certificate;
        try {
            certificate = CertTools.getCertfromByteArray(derEncodedCertificate);
        } catch (CertificateException e) {
            throw new CertificateImportException(e);
        }
        // Verify that this is an accepted type of certificate to import for the current implementation
        assertCertificateIsOkToImport(certificate, signerMapping);
        final int cryptoTokenId = signerMapping.getCryptoTokenId();
        final String currentKeyPairAlias = signerMapping.getKeyPairAlias();
        boolean updated = false;
        try {
            final PublicKey currentPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, currentKeyPairAlias);
            if (currentPublicKey != null && KeyTools.createSubjectKeyId(currentPublicKey).equals(KeyTools.createSubjectKeyId(certificate.getPublicKey()))) {
                // If current key matches current public key -> import + update signerMapping.certificateId
                storeCertificate(authenticationToken, signerMapping, certificate);
                signerMapping.setCertificateId(CertTools.getFingerprintAsString(certificate));
                updated = true;
            } else {
                final String nextKeyPairAlias = signerMapping.getNextKeyPairAlias();
                if (nextKeyPairAlias == null) {
                    final PublicKey nextPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, nextKeyPairAlias);
                    if (nextPublicKey != null && KeyTools.createSubjectKeyId(nextPublicKey).equals(KeyTools.createSubjectKeyId(certificate.getPublicKey()))) {
                        // If current key matches next public key -> import and update nextKey + signerMapping.certificateId
                        storeCertificate(authenticationToken, signerMapping, certificate);
                        signerMapping.updateCertificateIdAndCurrentKeyAlias(CertTools.getFingerprintAsString(certificate));
                        updated = true;
                    }
                }
            }
        } catch (CryptoTokenOfflineException e) {
            throw new CertificateImportException(e);
        }
        if (updated) {
            try {
                signerMappingDataSession.mergeSignerMapping(signerMapping);
            } catch (SignerMappingNameInUseException e) {
                // This would be very strange if it happened, since we use the same name and id as for the existing one
                throw new CertificateImportException(e);
            }
        } else {
            throw new CertificateImportException("No keys matching the certificate were found.");
        }
        throw new UnsupportedOperationException("Not yet fully implemented!");
    }
    
    /** Asserts that it is not a CA certificate and that the implementation finds it acceptable.  */
    private void assertCertificateIsOkToImport(Certificate certificate, SignerMapping signerMapping) throws CertificateImportException {
        // Do some general sanity checks that this is not a CA certificate
        if (CertTools.isCA(certificate)) {
            throw new CertificateImportException("Import of CA certificates is not allowed using this operation.");
        }
        // Check that this is an accepted type of certificate from the one who knows (the implementation)
        signerMapping.assertCertificateCompatability(certificate);
    }
    
    /** Imports the certificate to the database */
    private void storeCertificate(AuthenticationToken authenticationToken, SignerMapping signerMapping, Certificate certificate)
            throws AuthorizationDeniedException, CertificateImportException {
        // Set some values for things we cannot know
        final int certificateProfileId = 0;
        final String username = "IMPORTED_SignerMapping_" + signerMapping.getId();
        // Find caFingerprint through ca(Admin?)Session
        final List<Integer> availableCaIds = caSession.getAvailableCAs();
        final String issuerDn = CertTools.getIssuerDN(certificate);
        String caFingerprint = null;
        for (final Integer caId : availableCaIds) {
            try {
                final Certificate caCert = caSession.getCAInfo(authenticationToken, caId).getCertificateChain().iterator().next();
                final String subjectDn = CertTools.getSubjectDN(caCert);
                if (subjectDn.equals(issuerDn)) {
                    caFingerprint = CertTools.getFingerprintAsString(caCert);
                    break;
                }
            } catch (CADoesntExistsException e) {
                log.debug("CA with caId " + caId + "disappeared during this operation.");
            }
        }
        if (caFingerprint == null) {
            throw new CertificateImportException("No CA certificate for " + issuerDn + " was found on the system.");
        }
        try {
            certificateStoreSession.storeCertificate(authenticationToken, certificate, username, caFingerprint,
                    CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, certificateProfileId, null, System.currentTimeMillis());
        } catch (CreateException e) {
            throw new CertificateImportException(e);
        }
    }
}

