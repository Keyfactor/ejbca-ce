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
package org.cesecore.keybind;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NoSuchElementException;

import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CustomCertSerialNumberException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyPairInfo;
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
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
    @EJB
    private CertificateCreateSessionLocal certificateCreateSession;

    @SuppressWarnings("unchecked")
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<String, List<InternalKeyBindingProperty<? extends Serializable>>> getAvailableTypesAndProperties() {
        // Perform deep cloning (this will work since we know that the property types extend Serializable)
        final Map<String, List<InternalKeyBindingProperty<? extends Serializable>>> clone;
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(InternalKeyBindingFactory.INSTANCE.getAvailableTypesAndProperties());
            oos.close();
            final ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));
            clone = (Map<String, List<InternalKeyBindingProperty<? extends Serializable>>>) ois.readObject();
            ois.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        return clone;
    }

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
    public List<InternalKeyBindingInfo> getInternalKeyBindingInfos(AuthenticationToken authenticationToken, String internalKeyBindingType) {
        final List<Integer> authorizedIds = getInternalKeyBindingIds(authenticationToken, internalKeyBindingType);
        final List<InternalKeyBindingInfo> authorizedInternalKeyBindingInfos = new ArrayList<InternalKeyBindingInfo>(authorizedIds.size());
        for (final Integer current : authorizedIds) {
            final InternalKeyBinding internalKeyBindingInstance = internalKeyBindingDataSession.getInternalKeyBinding(current.intValue());
            authorizedInternalKeyBindingInfos.add(new InternalKeyBindingInfo(internalKeyBindingInstance));
        }
        return authorizedInternalKeyBindingInfos;
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
    public InternalKeyBindingInfo getInternalKeyBindingInfo(AuthenticationToken authenticationToken, int id) throws AuthorizationDeniedException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, InternalKeyBindingRules.VIEW.resource()+"/"+id)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", InternalKeyBindingRules.VIEW.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return new InternalKeyBindingInfo(internalKeyBindingDataSession.getInternalKeyBinding(id));
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
    public int createInternalKeyBinding(AuthenticationToken authenticationToken, String type, String name, InternalKeyBindingStatus status, String certificateId,
            int cryptoTokenId, String keyPairAlias, String signatureAlgorithm, Map<Object, Object> dataMap) throws AuthorizationDeniedException, CryptoTokenOfflineException,
            InternalKeyBindingNameInUseException, InvalidAlgorithmException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, InternalKeyBindingRules.MODIFY.resource(),
                CryptoTokenRules.USE.resource() + "/" + cryptoTokenId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", InternalKeyBindingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        if (!AlgorithmTools.isSigAlgEnabled(signatureAlgorithm)) {
            throw new InvalidAlgorithmException("Signature algorithm " + signatureAlgorithm + " is not available.");
        }
        // Convert supplied properties using a prefix to ensure that the caller can't mess with internal ones
        final LinkedHashMap<Object,Object> initDataMap = new LinkedHashMap<Object,Object>();
        if (dataMap != null) {
            for (final Entry<Object,Object> entry: dataMap.entrySet()) {
                String key = String.valueOf(entry.getKey());
                if (key.startsWith(InternalKeyBindingBase.SUBCLASS_PREFIX)) {
                    initDataMap.put(key, entry.getValue());
                } else {
                    initDataMap.put(InternalKeyBindingBase.SUBCLASS_PREFIX + key, entry.getValue());
                }
            }
        }
        // Check that CryptoToken and alias exists (and that the user is authorized to see it)
        final KeyPairInfo keyPairInfo = cryptoTokenManagementSession.getKeyPairInfo(authenticationToken, cryptoTokenId, keyPairAlias);
        if (keyPairInfo == null) {
            throw new CryptoTokenOfflineException("Unable to access keyPair with alias " + keyPairAlias + " in CryptoToken with id " + cryptoTokenId);
        }
        // If we created a new InternalKeyBinding without a certificate reference (e.g. will be uploaded later) we will not allow the status to be anything but "DISABLED"
        if (certificateId == null || certificateStoreSession.findCertificateByFingerprint(certificateId) == null) {
            status = InternalKeyBindingStatus.DISABLED;
        }
        // Finally, try to create an instance of this type and persist it
        final InternalKeyBinding internalKeyBinding = InternalKeyBindingFactory.INSTANCE.create(type, 0, name, status, certificateId,
                cryptoTokenId, keyPairAlias, initDataMap);
        internalKeyBinding.setSignatureAlgorithm(signatureAlgorithm);
        return internalKeyBindingDataSession.mergeInternalKeyBinding(internalKeyBinding);
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
    public String generateNextKeyPair(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException,
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
        return nextKeyPairAlias;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public byte[] getNextPublicKeyForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, InternalKeyBindingRules.VIEW.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", InternalKeyBindingRules.VIEW.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBindingId);
        return getNextPublicKeyForInternalKeyBinding(authenticationToken, internalKeyBinding).getEncoded();
    }
    
    private PublicKey getNextPublicKeyForInternalKeyBinding(AuthenticationToken authenticationToken, InternalKeyBinding internalKeyBinding)
            throws CryptoTokenOfflineException, AuthorizationDeniedException {
        final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        final String nextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
        final String keyPairAlias;
        if (nextKeyPairAlias == null) {
            keyPairAlias = internalKeyBinding.getKeyPairAlias();
        } else {
            keyPairAlias = nextKeyPairAlias;
        }
        final PublicKey publicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, keyPairAlias);
        return publicKey;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public byte[] generateCsrForNextKey(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException, CryptoTokenOfflineException {
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
        // Chose first available signature algorithm
        final Collection<String> availableSignatureAlgorithms = AlgorithmTools.getSignatureAlgorithms(publicKey);
        final String signatureAlgorithm = availableSignatureAlgorithms.iterator().next();
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(cryptoTokenId);
        final PrivateKey privateKey = cryptoToken.getPrivateKey(keyPairAlias);
        final X500Name x500Name = CertTools.stringToBcX500Name("CN=Should be ignore by CA");
        final String providerName = cryptoToken.getSignProviderName();
        try {
            return CertTools.genPKCS10CertificationRequest(signatureAlgorithm, x500Name, publicKey, new DERSet(), privateKey, providerName).getEncoded();
        } catch (OperatorCreationException e) {
            log.info("CSR generation failed. internalKeyBindingId=" + internalKeyBindingId + ", cryptoTokenId=" + cryptoTokenId + ", keyPairAlias=" + keyPairAlias + ". " + e.getMessage());
        } catch (IOException e) {
            log.info("CSR generation failed. internalKeyBindingId=" + internalKeyBindingId + ", cryptoTokenId=" + cryptoTokenId + ", keyPairAlias=" + keyPairAlias + ". " + e.getMessage());
        }
        return null;
    }

    @Override
    public String updateCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId)
            throws AuthorizationDeniedException, CertificateImportException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, InternalKeyBindingRules.MODIFY.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", InternalKeyBindingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBindingId);
        final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        final String nextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
        if (log.isDebugEnabled()) {
            log.debug("nextKeyPairAlias: " + nextKeyPairAlias);
        }
        boolean updated = false;
        if (nextKeyPairAlias != null) {
            // If a nextKeyPairAlias is present we assume that this is the one we want to find a certificate for
            PublicKey nextPublicKey;
            try {
                nextPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, nextKeyPairAlias);
            } catch (CryptoTokenOfflineException e) {
                throw new CertificateImportException("Operation is not available when CryptoToken is offline.", e);
            }
            if (nextPublicKey != null) {
                final byte[] subjectKeyId = KeyTools.createSubjectKeyId(nextPublicKey).getKeyIdentifier();
                final Certificate certificate = certificateStoreSession.findMostRecentlyUpdatedActiveCertificate(subjectKeyId);
                if (certificate == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("No certificate found for " + nextKeyPairAlias);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Certificate found for " + nextKeyPairAlias);
                    }
                    // Verify that this is an accepted type of certificate to import for the current implementation
                    assertCertificateIsOkToImport(certificate, internalKeyBinding);
                    // If current key matches next public key -> import and update nextKey + certificateId
                    String fingerprint = CertTools.getFingerprintAsString(certificate);
                    if (!fingerprint.equals(internalKeyBinding.getCertificateId())) {
                        internalKeyBinding.updateCertificateIdAndCurrentKeyAlias(fingerprint);
                        updated = true;
                        if (log.isDebugEnabled()) {
                            log.debug("New certificate with fingerprint " + fingerprint + " matching " + nextKeyPairAlias + " will be used.");
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("The latest available certificate was already in use.");
                        }
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("There was no public key for the referenced alias " + nextKeyPairAlias);
                }
            }
        }
        if (!updated) {
            // We failed to find a matching certificate for the next key, so we instead try to do the same for the current key pair
            final String currentKeyPairAlias = internalKeyBinding.getKeyPairAlias();
            log.debug("currentKeyPairAlias: " + currentKeyPairAlias);
            PublicKey currentPublicKey;
            try {
                currentPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, currentKeyPairAlias);
            } catch (CryptoTokenOfflineException e) {
                throw new CertificateImportException("Operation is not available when CryptoToken is offline.", e);
            }
            if (currentPublicKey != null) {
                final byte[] subjectKeyId = KeyTools.createSubjectKeyId(currentPublicKey).getKeyIdentifier();
                final Certificate certificate = certificateStoreSession.findMostRecentlyUpdatedActiveCertificate(subjectKeyId);
                if (certificate == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("No certificate found for " + currentKeyPairAlias);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Certificate found for " + currentKeyPairAlias);
                    }
                    // Verify that this is an accepted type of certificate to import for the current implementation
                    assertCertificateIsOkToImport(certificate, internalKeyBinding);
                    final String fingerprint = CertTools.getFingerprintAsString(certificate);
                    if (!fingerprint.equals(internalKeyBinding.getCertificateId())) {
                        internalKeyBinding.setCertificateId(fingerprint);
                        updated = true;
                        if (log.isDebugEnabled()) {
                            log.debug("Certificate with fingerprint " + fingerprint + " matching " + currentKeyPairAlias + " will be used.");
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("The latest available certificate was already in use.");
                        }
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("There was no public key for the referenced alias " + currentKeyPairAlias);
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
            if (log.isDebugEnabled()) {
                log.debug("No certificate found for " + nextKeyPairAlias);
            }
            return internalKeyBinding.getCertificateId();
        }
        return null;
    }


    @Override
    public boolean setStatus(AuthenticationToken authenticationToken, int internalKeyBindingId, InternalKeyBindingStatus status) throws AuthorizationDeniedException {
        final InternalKeyBinding internalKeyBinding = getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        if (status == internalKeyBinding.getStatus()) {
            return false;
        }
        internalKeyBinding.setStatus(status);
        try {
            persistInternalKeyBinding(authenticationToken, internalKeyBinding);
        } catch (InternalKeyBindingNameInUseException e) {
            // This would be very strange if it happened, since we use the same name and id as for the existing one
            throw new RuntimeException(e);
        }
        return true;
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
        if (log.isDebugEnabled()) {
            log.debug("certificate.getPublicKey(): " + new String(Hex.encode(KeyTools.createSubjectKeyId(certificate.getPublicKey()).getKeyIdentifier())));
            log.debug("currentKeyPairAlias: " + currentKeyPairAlias);
        }
        boolean updated = false;
        try {
            String certificateId = CertTools.getFingerprintAsString(certificate);
            final PublicKey currentPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, currentKeyPairAlias);
            if (log.isDebugEnabled()) {
                log.debug("currentPublicKey: " + (currentPublicKey != null ?
                    new String(Hex.encode(KeyTools.createSubjectKeyId(currentPublicKey).getKeyIdentifier())) : "null"));
            }
            if (currentPublicKey != null && KeyTools.createSubjectKeyId(currentPublicKey).equals(KeyTools.createSubjectKeyId(certificate.getPublicKey()))) {
                // If current key matches current public key -> import + update certificateId
                if (isCertificateAlreadyInDatabase(certificateId)) {
                    log.info("Certificate with fingerprint " + certificateId + " was already present in the database. Only InternalKeyBinding reference will be updated.");
                } else {
                    storeCertificate(authenticationToken, internalKeyBinding, certificate);
                }
                internalKeyBinding.setCertificateId(certificateId);
                updated = true;
            } else {
                final String nextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
                if (log.isDebugEnabled()) {
                    log.debug("nextKeyPairAlias: " + nextKeyPairAlias);
                }
                if (nextKeyPairAlias != null) {
                    final PublicKey nextPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, nextKeyPairAlias);
                    if (log.isDebugEnabled()) {
                        log.debug("nextPublicKey: " + (nextPublicKey != null ?
                            new String(Hex.encode(KeyTools.createSubjectKeyId(nextPublicKey).getKeyIdentifier())) : "null"));
                    }
                    if (nextPublicKey != null && KeyTools.createSubjectKeyId(nextPublicKey).equals(KeyTools.createSubjectKeyId(certificate.getPublicKey()))) {
                        // If current key matches next public key -> import and update nextKey + certificateId
                        if (isCertificateAlreadyInDatabase(certificateId)) {
                            log.info("Certificate with fingerprint " + certificateId + " was already present in the database. Only InternalKeyBinding reference will be updated.");
                        } else {
                            storeCertificate(authenticationToken, internalKeyBinding, certificate);
                        }
                        internalKeyBinding.updateCertificateIdAndCurrentKeyAlias(certificateId);
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
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public String renewInternallyIssuedCertificate(AuthenticationToken authenticationToken, int internalKeyBindingId,
            EndEntityInformation endEntityInformation)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CertificateImportException {
        // Assert authorization
        assertAuthorization(authenticationToken, InternalKeyBindingRules.MODIFY.resource() + "/" + internalKeyBindingId);
        if (endEntityInformation == null) {
            throw new CertificateImportException("Cannot renew certificate without an existing end entity.");
        }
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBindingId);
        final String endEntityId = certificateStoreSession.findUsernameByFingerprint(internalKeyBinding.getCertificateId());
        if (endEntityId == null || !endEntityId.equals(endEntityInformation.getUsername())) {
            // We expect renewals to re-use the same end entity template as before
            throw new CertificateImportException("Not allowed to switch end entity during renewal.");
        }
        final PublicKey publicKey = getNextPublicKeyForInternalKeyBinding(authenticationToken, internalKeyBinding);
        final RequestMessage req = new SimpleRequestMessage(publicKey, endEntityInformation.getUsername(), endEntityInformation.getPassword());
        final CertificateResponseMessage response;
        try {
            response = certificateCreateSession.createCertificate(authenticationToken, endEntityInformation, req, X509ResponseMessage.class);
        } catch (CustomCertSerialNumberException e) {
            throw new CertificateImportException(e);
        } catch (IllegalKeyException e) {
            throw new CertificateImportException(e);
        } catch (CADoesntExistsException e) {
            throw new CertificateImportException(e);
        } catch (CertificateCreateException e) {
            throw new CertificateImportException(e);
        } catch (CesecoreException e) {
            throw new CertificateImportException(e);
        }
        final String newCertificateId = updateCertificateForInternalKeyBinding(authenticationToken, internalKeyBindingId);
        if (newCertificateId == null) {
            throw new CertificateImportException("New certificate was never issued.");
        }
        // Sanity check that the certificate we issued is the one that is in use
        final X509Certificate keyBindingCertificate = (X509Certificate) response.getCertificate();
        if (!newCertificateId.equals(CertTools.getFingerprintAsString(keyBindingCertificate))) {
            throw new CertificateImportException("Issued certificate was not found in database. Throw-away setting for issuing CA is not allowed for InternalKeyBindings.");
        }
        return newCertificateId;
    }
    
    private void assertAuthorization(AuthenticationToken authenticationToken, final String...rules) throws AuthorizationDeniedException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, rules)) {
            if (rules.length == 1) {
                final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", rules[0], authenticationToken.toString());
                throw new AuthorizationDeniedException(msg);
            } else {
                final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", Arrays.toString(rules), authenticationToken.toString());
                throw new AuthorizationDeniedException(msg);
            }
        }
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
    
    /** @return true if a certificate with the specified certificateId (fingerprint) already exists in the database */
    private boolean isCertificateAlreadyInDatabase(String certificateId) {
        return certificateStoreSession.findCertificateByFingerprint(certificateId) != null;
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
                log.debug("CA with caId " + caId + " disappeared during this operation.");
            } catch (NoSuchElementException e) {
                log.debug("CA with caId " + caId + " has no certificate chain.");
            }
        }
        if (caFingerprint == null) {
            throw new CertificateImportException("No CA certificate for " + issuerDn + " was found on the system.");
        }
        try {
            certificateStoreSession.storeCertificate(authenticationToken, certificate, username, caFingerprint,
                    CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, certificateProfileId, null, System.currentTimeMillis());
        } catch (CreateException e) {
            // Just pass on the message, in case this is a remote invocation where the underlying class is not available.
            if (log.isDebugEnabled()) {
                log.debug("", e);
            }
            throw new CertificateImportException(e.getMessage());
        }
    }
}

