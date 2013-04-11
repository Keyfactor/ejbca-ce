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
 * Generic Management implementation for InternalKeyBindings.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "InternalKeyBindingMgmtSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class InternalKeyBindingMgmtSessionBean implements InternalKeyBindingMgmtSessionLocal, InternalKeyBindingMgmtSessionRemote {

    private static final Logger log = Logger.getLogger(InternalKeyBindingMgmtSessionBean.class);
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
    private InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getInternalKeyBindingIds(AuthenticationToken authenticationToken, String internalKeyBindingType) {
        final List<Integer> allIds = internalKeyBindingDataSession.getIds(internalKeyBindingType);
        final List<Integer> authorizedIds = new ArrayList<Integer>();
        for (final Integer current : allIds) {
            if (accessControlSessionSession.isAuthorizedNoLogging(authenticationToken, InternalKeyBindingRules.VIEW.resource()+"/"+current.toString())) {
                authorizedIds.add(current);
            }
        }
        return authorizedIds;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public InternalKeyBinding getInternalKeyBinding(AuthenticationToken authenticationToken, int id) throws AuthorizationDeniedException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, InternalKeyBindingRules.VIEW.resource()+"/"+id)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", InternalKeyBindingRules.VIEW.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return internalKeyBindingDataSession.getInternalKeyBinding(id);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Integer getIdFromName(String internalKeyBindingName) {
        if (internalKeyBindingName==null) {
            return null;
        }
        final Map<String, Integer> cachedNameToIdMap = internalKeyBindingDataSession.getCachedNameToIdMap();
        Integer internalKeyBindingId = cachedNameToIdMap.get(internalKeyBindingName);
        if (internalKeyBindingId == null) {
            // Ok.. so it's not in the cache.. look for it the hard way..
            for (final Integer currentId : internalKeyBindingDataSession.getIds(null)) {
                // Don't lookup CryptoTokens we already have in the id to name cache
                if (!cachedNameToIdMap.keySet().contains(currentId)) {
                    final InternalKeyBinding current = internalKeyBindingDataSession.getInternalKeyBinding(currentId.intValue());
                    final String currentName = current == null ? null : current.getName();
                    if (internalKeyBindingName.equals(currentName)) {
                        internalKeyBindingId = currentId;
                        break;
                    }
                }
            }
        }
        return internalKeyBindingId;
    }

    @Override
    public int persistInternalKeyBinding(AuthenticationToken authenticationToken, InternalKeyBinding internalKeyBinding)
            throws AuthorizationDeniedException, InternalKeyBindingNameInUseException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, InternalKeyBindingRules.MODIFY.resource()+"/"+internalKeyBinding.getId(),
                CryptoTokenRules.USE.resource()+"/"+internalKeyBinding.getCryptoTokenId())) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", InternalKeyBindingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return internalKeyBindingDataSession.mergeInternalKeyBinding(internalKeyBinding);
    }

    @Override
    public boolean deleteInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, InternalKeyBindingRules.DELETE.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", InternalKeyBindingRules.DELETE.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return internalKeyBindingDataSession.removeInternalKeyBinding(internalKeyBindingId);
    }

    @Override
    public void generateNextKeyPair(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException,
            CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, InternalKeyBindingRules.MODIFY.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", InternalKeyBindingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBindingId);
        final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        final String currentKeyPairAlias = internalKeyBinding.getKeyPairAlias();
        internalKeyBinding.generateNextKeyPairAlias();
        final String nextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
        cryptoTokenManagementSession.createKeyPairWithSameKeySpec(authenticationToken, cryptoTokenId, currentKeyPairAlias, nextKeyPairAlias);
        try {
            internalKeyBindingDataSession.mergeInternalKeyBinding(internalKeyBinding);
        } catch (InternalKeyBindingNameInUseException e) {
            // This would be very strange if it happened, since we use the same name and id as for the existing one
            throw new RuntimeException(e);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public byte[] getNextPublicKeyForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, InternalKeyBindingRules.VIEW.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", InternalKeyBindingRules.VIEW.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBindingId);
        final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        final String nextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
        final String keyPairAlias;
        if (nextKeyPairAlias == null) {
            keyPairAlias = internalKeyBinding.getKeyPairAlias();
        } else {
            keyPairAlias = nextKeyPairAlias;
        }
        final PublicKey publicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, keyPairAlias);
        return publicKey.getEncoded();
    }

    @Override
    public void updateCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId)
            throws AuthorizationDeniedException, CertificateImportException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, InternalKeyBindingRules.MODIFY.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", InternalKeyBindingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBindingId);
        final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        final String nextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
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
                    assertCertificateIsOkToImport(certificate, internalKeyBinding);
                    // If current key matches next public key -> import and update nextKey + certificateId
                    String fingerprint = CertTools.getFingerprintAsString(certificate);
                    if (!fingerprint.equals(internalKeyBinding.getCertificateId())) {
                        internalKeyBinding.updateCertificateIdAndCurrentKeyAlias(fingerprint);
                        updated = true;
                    } else {
                        log.debug("The latest available certificate was already in use.");
                    }
                }
            }
        }
        if (!updated) {
            // We failed to find a matching certificate for the next key, so we instead try to do the same for the current key pair
            final String currentKeyPairAlias = internalKeyBinding.getKeyPairAlias();
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
                    assertCertificateIsOkToImport(certificate, internalKeyBinding);
                    String fingerprint = CertTools.getFingerprintAsString(certificate);
                    internalKeyBinding.setCertificateId(fingerprint);
                    updated = true;
                }
            }
        }
        if (updated) {
            try {
                internalKeyBindingDataSession.mergeInternalKeyBinding(internalKeyBinding);
            } catch (InternalKeyBindingNameInUseException e) {
                // This would be very strange if it happened, since we use the same name and id as for the existing one
                throw new CertificateImportException(e);
            }
        } else {
            throw new CertificateImportException("No certificate matching the keys were found.");
        }
    }

    @Override
    public void importCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId, byte[] derEncodedCertificate)
            throws AuthorizationDeniedException, CertificateImportException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, InternalKeyBindingRules.MODIFY.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", InternalKeyBindingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBindingId);
        // UnDERify
        final Certificate certificate;
        try {
            certificate = CertTools.getCertfromByteArray(derEncodedCertificate);
        } catch (CertificateException e) {
            throw new CertificateImportException(e);
        }
        // Verify that this is an accepted type of certificate to import for the current implementation
        assertCertificateIsOkToImport(certificate, internalKeyBinding);
        final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        final String currentKeyPairAlias = internalKeyBinding.getKeyPairAlias();
        boolean updated = false;
        try {
            final PublicKey currentPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, currentKeyPairAlias);
            if (currentPublicKey != null && KeyTools.createSubjectKeyId(currentPublicKey).equals(KeyTools.createSubjectKeyId(certificate.getPublicKey()))) {
                // If current key matches current public key -> import + update certificateId
                storeCertificate(authenticationToken, internalKeyBinding, certificate);
                internalKeyBinding.setCertificateId(CertTools.getFingerprintAsString(certificate));
                updated = true;
            } else {
                final String nextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
                if (nextKeyPairAlias == null) {
                    final PublicKey nextPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, nextKeyPairAlias);
                    if (nextPublicKey != null && KeyTools.createSubjectKeyId(nextPublicKey).equals(KeyTools.createSubjectKeyId(certificate.getPublicKey()))) {
                        // If current key matches next public key -> import and update nextKey + certificateId
                        storeCertificate(authenticationToken, internalKeyBinding, certificate);
                        internalKeyBinding.updateCertificateIdAndCurrentKeyAlias(CertTools.getFingerprintAsString(certificate));
                        updated = true;
                    }
                }
            }
        } catch (CryptoTokenOfflineException e) {
            throw new CertificateImportException(e);
        }
        if (updated) {
            try {
                internalKeyBindingDataSession.mergeInternalKeyBinding(internalKeyBinding);
            } catch (InternalKeyBindingNameInUseException e) {
                // This would be very strange if it happened, since we use the same name and id as for the existing one
                throw new CertificateImportException(e);
            }
        } else {
            throw new CertificateImportException("No keys matching the certificate were found.");
        }
        throw new UnsupportedOperationException("Not yet fully implemented!");
    }
    
    /** Asserts that it is not a CA certificate and that the implementation finds it acceptable.  */
    private void assertCertificateIsOkToImport(Certificate certificate, InternalKeyBinding internalKeyBinding) throws CertificateImportException {
        // Do some general sanity checks that this is not a CA certificate
        if (CertTools.isCA(certificate)) {
            throw new CertificateImportException("Import of CA certificates is not allowed using this operation.");
        }
        // Check that this is an accepted type of certificate from the one who knows (the implementation)
        internalKeyBinding.assertCertificateCompatability(certificate);
    }
    
    /** Imports the certificate to the database */
    private void storeCertificate(AuthenticationToken authenticationToken, InternalKeyBinding internalKeyBinding, Certificate certificate)
            throws AuthorizationDeniedException, CertificateImportException {
        // Set some values for things we cannot know
        final int certificateProfileId = 0;
        final String username = "IMPORTED_InternalKeyBinding_" + internalKeyBinding.getId();
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

