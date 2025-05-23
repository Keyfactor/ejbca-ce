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
package org.cesecore.keybind;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NoSuchElementException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.pinning.CertificatePin;
import org.cesecore.certificates.pinning.TrustEntry;
import org.cesecore.certificates.pinning.TrustedChain;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.util.ui.DynamicUiProperty;

import com.keyfactor.CesecoreException;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.KeyGenParams.KeyGenParamsBuilder;
import com.keyfactor.util.keys.token.KeyGenParams.KeyPairTemplate;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

/**
 * Generic Management implementation for InternalKeyBindings.
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class InternalKeyBindingMgmtSessionBean implements InternalKeyBindingMgmtSessionLocal, InternalKeyBindingMgmtSessionRemote {

    private static final Logger log = Logger.getLogger(InternalKeyBindingMgmtSessionBean.class);
    private static final InternalResources intres = InternalResources.getInstance();

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateDataSessionLocal certificateDataSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
    @EJB
    private CertificateCreateSessionLocal certificateCreateSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @SuppressWarnings("unchecked")
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<String, Map<String, DynamicUiProperty<? extends Serializable>>> getAvailableTypesAndProperties() {
        // Perform deep cloning (this will work since we know that the property types extend Serializable)
        final Map<String, Map<String, DynamicUiProperty<? extends Serializable>>> clone;
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(InternalKeyBindingFactory.INSTANCE.getAvailableTypesAndProperties());
            oos.close();
            final ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));
            clone = (Map<String, Map<String, DynamicUiProperty<? extends Serializable>>>) ois.readObject();
            ois.close();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        return clone;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getInternalKeyBindingIds(String internalKeyBindingType) {
        return internalKeyBindingDataSession.getIds(internalKeyBindingType);
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getInternalKeyBindingIds(AuthenticationToken authenticationToken, String internalKeyBindingType) {
        final List<Integer> allIds = internalKeyBindingDataSession.getIds(internalKeyBindingType);
        final List<Integer> authorizedIds = new ArrayList<>();
        for (final Integer current : allIds) {
            if (authorizationSession.isAuthorizedNoLogging(authenticationToken,
                    InternalKeyBindingRules.VIEW.resource() + "/" + current.toString())) {
                authorizedIds.add(current);
            }
        }
        return authorizedIds;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<InternalKeyBindingInfo> getInternalKeyBindingInfos(AuthenticationToken authenticationToken, String internalKeyBindingType) {
        final List<Integer> authorizedIds = getInternalKeyBindingIds(authenticationToken, internalKeyBindingType);
        final List<InternalKeyBindingInfo> authorizedInternalKeyBindingInfos = new ArrayList<>(authorizedIds.size());
        for (final Integer current : authorizedIds) {
            final InternalKeyBinding internalKeyBindingInstance = internalKeyBindingDataSession.getInternalKeyBinding(current);
            authorizedInternalKeyBindingInfos.add(new InternalKeyBindingInfo(internalKeyBindingInstance));
        }
        return authorizedInternalKeyBindingInfos;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<InternalKeyBindingInfo> getAllInternalKeyBindingInfos(String internalKeyBindingType) {
        final List<Integer> ids = internalKeyBindingDataSession.getIds(internalKeyBindingType);
        final List<InternalKeyBindingInfo> internalKeyBindingInfos = new ArrayList<>(ids.size());
        for (final Integer current : ids) {
            final InternalKeyBinding internalKeyBindingInstance = internalKeyBindingDataSession.getInternalKeyBinding(current);
            internalKeyBindingInfos.add(new InternalKeyBindingInfo(internalKeyBindingInstance));
        }
        return internalKeyBindingInfos;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<Integer, String> getAllCaWithoutOcspKeyBinding() {
        final List<InternalKeyBindingInfo> allOcspKeyBindings = 
                getAllInternalKeyBindingInfos(OcspKeyBinding.IMPLEMENTATION_ALIAS);
        List<Integer> internalKeyBoundCas = new ArrayList<Integer>();
        for(InternalKeyBindingInfo keyBindingInfo: allOcspKeyBindings) {
            if(keyBindingInfo.getStatus()==null 
                    || (keyBindingInfo.getStatus()==InternalKeyBindingStatus.DISABLED && 
                            keyBindingInfo.getCertificateId()!=null) ) {
                // this allows an Admin to disable an OCspKeyBinding and create new one with signOnBehalf entry
                // instead of deleting the old entry 
                // while taking in account for the period before signed CSR is uploaded 
                continue;
            }
            for(InternalKeyBindingTrustEntry signOnBehalfEntry : keyBindingInfo.getSignOcspResponseOnBehalf()) {
                internalKeyBoundCas.add(signOnBehalfEntry.getCaId());
            }
        }
        
        final Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();        
        for(Integer internalKeyBoundCa: internalKeyBoundCas) {
            caIdToNameMap.remove(internalKeyBoundCa);
        }
        
        return caIdToNameMap;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<Integer, String> getAllInternalKeyBindingIdNameMap(String internalKeyBindingType) {
        final Map<Integer, String> idNameMap = new HashMap<>();
        final List<Integer> ids = internalKeyBindingDataSession.getIds(internalKeyBindingType);
        for (final Integer id : ids) {
            final InternalKeyBinding internalKeyBindingInstance = internalKeyBindingDataSession.getInternalKeyBinding(id);
            idNameMap.put(id, internalKeyBindingInstance.getName());
        }
        return idNameMap;
    }

    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public InternalKeyBinding getInternalKeyBindingReference(AuthenticationToken authenticationToken, int id) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(authenticationToken, InternalKeyBindingRules.VIEW.resource() + "/" + id)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.VIEW.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return internalKeyBindingDataSession.getInternalKeyBinding(id);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public InternalKeyBinding getInternalKeyBinding(AuthenticationToken authenticationToken, int id) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(authenticationToken, InternalKeyBindingRules.VIEW.resource() + "/" + id)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.VIEW.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return internalKeyBindingDataSession.getInternalKeyBindingForEdit(id);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public InternalKeyBindingInfo getInternalKeyBindingInfo(AuthenticationToken authenticationToken, int id) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(authenticationToken, InternalKeyBindingRules.VIEW.resource() + "/" + id)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.VIEW.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final InternalKeyBinding b = internalKeyBindingDataSession.getInternalKeyBinding(id);
        if (b == null) {
            return null;
        }
        return new InternalKeyBindingInfo(b);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public InternalKeyBindingInfo getInternalKeyBindingInfoNoLog(AuthenticationToken authenticationToken, int id) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, InternalKeyBindingRules.VIEW.resource() + "/" + id)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.VIEW.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBinding(id);
        if (internalKeyBinding==null) {
            return null;
        }
        return new InternalKeyBindingInfo(internalKeyBinding);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Integer getIdFromName(String internalKeyBindingName) {
        if (internalKeyBindingName == null) {
            return null;
        }
        final Map<String, Integer> cachedNameToIdMap = internalKeyBindingDataSession.getCachedNameToIdMap();
        Integer internalKeyBindingId = cachedNameToIdMap.get(internalKeyBindingName);
        if (internalKeyBindingId == null) {
            // Ok.. so it's not in the cache.. look for it the hard way..
            for (final Integer currentId : internalKeyBindingDataSession.getIds(null)) {
                // Don't lookup CryptoTokens we already have in the id to name cache
                if (!cachedNameToIdMap.containsValue(currentId)) {
                    final InternalKeyBinding current = internalKeyBindingDataSession.getInternalKeyBinding(currentId);
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
    public List<TrustEntry> getTrustEntries(InternalKeyBinding internalKeyBinding) {
        final List<InternalKeyBindingTrustEntry> trustedReferences = internalKeyBinding.getTrustedCertificateReferences();

        List<TrustEntry> trustedEntries = new ArrayList<>();
        if (trustedReferences.size() == 0) {
            // If no trusted certificates are referenced, trust ANY certificates issued by ANY CA known to this EJBCA instance.
            // This is done by adding all CA certificate chains
            List<Integer> allCAs = caSession.getAllCaIds();
            for(int caid : allCAs) {
                final CAInfo caInfo = caSession.getCAInfoInternal(caid);
                if (caInfo instanceof X509CAInfo) { // ignore CVC CAs
                    // Quick and dirty cast
                    final List<Certificate> certificateChain = caInfo.getCertificateChain();
                    final List<X509Certificate> x509CertificateChain = new ArrayList<>(
                            Arrays.asList(certificateChain.toArray(new X509Certificate[certificateChain.size()])));
                    if (!x509CertificateChain.isEmpty()) {
                        trustedEntries.add(new TrustedChain(x509CertificateChain));
                    }
                    addOlderActiveCAsWithSameSubjectDN(trustedEntries, caInfo, certificateChain, null);
                }
            }
            if(log.isDebugEnabled()) {
                log.debug("Trusted Certificates list is empty. Trust ANY certificates issued by ANY CA known to this EJBCA instance");
            }
        } else {
            for (final InternalKeyBindingTrustEntry trustedReference : trustedReferences) {
                final CAInfo caInfo = caSession.getCAInfoInternal(trustedReference.getCaId());
                if (trustedReference.fetchCertificateSerialNumber() == null) {
                    // If no cert serialnumber is specified, then we trust all certificates issued by this CA. We add the entire
                    // CA certificate chain to be used for issuer verification
                    final List<Certificate> certificateChain = caInfo.getCertificateChain();
                    final List<X509Certificate> x509CertificateChain = new ArrayList<>(
                            Arrays.asList(certificateChain.toArray(new X509Certificate[certificateChain.size()])));
                    trustedEntries.add(new TrustedChain(x509CertificateChain));
                    // check for existing active certificates with same DN, but not in chain (certificate renewed with same SubjectDn)
                    addOlderActiveCAsWithSameSubjectDN(trustedEntries, caInfo, certificateChain, null);
                } else {
                    // If a cert serialnumber is specified, then we trust only the certificate with the serial number specified
                    // in the trustedReference
                    final List<Certificate> certificateChain = caInfo.getCertificateChain();
                    final List<X509Certificate> x509CertificateChain = new ArrayList<>(
                            Arrays.asList(certificateChain.toArray(new X509Certificate[certificateChain.size()])));
                    trustedEntries.add(new CertificatePin(x509CertificateChain, trustedReference.fetchCertificateSerialNumber()));
                    // check for existing active certificates with same DN, but not in chain (certificate renewed with same SubjectDn)
                    addOlderActiveCAsWithSameSubjectDN(trustedEntries, caInfo, certificateChain, trustedReference.fetchCertificateSerialNumber());
                }
            }
        }

        if (trustedEntries.size() == 0) {
            // If the trusted certificates list is empty it mean that the only trusted reference was to a non-existing specific certificate.
            // In this case, EJBCA should not trust anything
            return null;
        }
        return trustedEntries;
    }

    private void addOlderActiveCAsWithSameSubjectDN(List<TrustEntry> trustedEntries, final CAInfo caInfo, final List<Certificate> certificateChain, BigInteger serialNumber) {
        // check for existing active certificates with same DN, but not in chain (certificate renewed with same SubjectDn)
        List<Certificate> activeCaCertsBySubjectDn = certificateDataSession.findActiveBySubjectDnAndType(caInfo.getSubjectDN(),
                Arrays.asList(CertificateConstants.CERTTYPE_SUBCA, CertificateConstants.CERTTYPE_ROOTCA));
        for (Certificate caCertificate : activeCaCertsBySubjectDn) {
            if (!certificateChain.contains(caCertificate)) {
                final List<X509Certificate> renewedCertificateChain = new ArrayList<>();
                renewedCertificateChain.add((X509Certificate) caCertificate);
                if (serialNumber == null) {
                    trustedEntries.add(new TrustedChain(renewedCertificateChain));
                } else {
                    trustedEntries.add(new CertificatePin((renewedCertificateChain), serialNumber));
                }
            }
        }
    }


    @Override
    public int createInternalKeyBinding(AuthenticationToken authenticationToken, String type, int id, String name, InternalKeyBindingStatus status,
            String certificateId, int cryptoTokenId, String keyPairAlias, String signatureAlgorithm, Map<String, Serializable> dataMap,
            List<InternalKeyBindingTrustEntry> trustedCertificateReferences)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException, 
                InternalKeyBindingNonceConflictException {
        return createInternalKeyBinding(authenticationToken, type, id, name, status,
            certificateId, cryptoTokenId, keyPairAlias, false, signatureAlgorithm, dataMap,
            trustedCertificateReferences);
    }
    
    @Override
    public int createInternalKeyBinding(AuthenticationToken authenticationToken, String type, int id, String name, InternalKeyBindingStatus status,
            String certificateId, int cryptoTokenId, String keyPairAlias, boolean allowMissingKeyPair, String signatureAlgorithm, Map<String, Serializable> dataMap,
            List<InternalKeyBindingTrustEntry> trustedCertificateReferences)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException, 
                InternalKeyBindingNonceConflictException {
        return createInternalKeyBindingWithOptionalEnrollmentInfo(authenticationToken, type, id, name, status, certificateId, cryptoTokenId, keyPairAlias, 
                allowMissingKeyPair, signatureAlgorithm, dataMap, trustedCertificateReferences, 
                null, null, null, null, null);
    }

    @Override
    public int createInternalKeyBindingWithOptionalEnrollmentInfo(AuthenticationToken authenticationToken, String type, int id, String name, InternalKeyBindingStatus status,
            String certificateId, int cryptoTokenId, String keyPairAlias, boolean allowMissingKeyPair, String signatureAlgorithm, Map<String, Serializable> dataMap,
            List<InternalKeyBindingTrustEntry> trustedCertificateReferences, String subjectDn, String issuerDn, 
            String certificateProfileName, String endEntityProfileName, String keySpec)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException, 
                InternalKeyBindingNonceConflictException {
        if (!authorizationSession.isAuthorized(authenticationToken, InternalKeyBindingRules.MODIFY.resource(), CryptoTokenRules.USE.resource()
                + "/" + cryptoTokenId)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.MODIFY.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        // Convert supplied properties using a prefix to ensure that the caller can't mess with internal ones
        final LinkedHashMap<Object, Object> initDataMap = new LinkedHashMap<>();
        if (dataMap != null) {            
            for (final Entry<String, Serializable> entry : dataMap.entrySet()) {
                final String key = entry.getKey();
                if ("enableNonce".equals(key) && "true".equals(entry.getValue().toString()) && certificateId != null) {
                    final CertificateDataWrapper certificateDataWrapper = certificateStoreSession.getCertificateData(certificateId);
                    if (certificateDataWrapper == null)  {
                        continue;
                    }
                    final CertificateData certificateData = certificateDataWrapper.getCertificateData();
                    final String caFingerprint = certificateData.getCaFingerprint();
                    final CertificateDataWrapper caCertificateDataWrapper = certificateStoreSession.getCertificateData(caFingerprint);
                    if (caCertificateDataWrapper == null)  {
                        continue;
                    }
                    final CertificateData caCertificateData = certificateDataWrapper.getCertificateData();
                    final String base64Cert = caCertificateData.getBase64Cert();
                    
                    final List<CAInfo> caInfos = caSession.getAuthorizedCaInfos(authenticationToken);
                    for (CAInfo caInfo : caInfos) {
                        if (CAInfo.CATYPE_X509 == caInfo.getCAType() && caInfo.getCertificateChain() != null && !caInfo.getCertificateChain().isEmpty()) {
                            final String caCert = caInfo.getCertificateChain().get(0).toString();
                            if (caCert.equals(base64Cert) && ((X509CAInfo)caInfo).isDoPreProduceOcspResponses()) {
                                throw new InternalKeyBindingNonceConflictException("Can not create OCSP Key Binding with nonce enabled in response when"
                                        + "the associated CA has pre-production of OCSP responses enabled.");
                            }                            
                        }
                    }
                }
                if (key.startsWith(InternalKeyBindingBase.SUBCLASS_PREFIX)) {
                    initDataMap.put(key, entry.getValue());
                } else {
                    initDataMap.put(InternalKeyBindingBase.SUBCLASS_PREFIX + key, entry.getValue());
                }
            }
        }
        if (!allowMissingKeyPair) {
            // Check that CryptoToken and alias exists (and that the user is authorized to see it)
            final KeyPairInfo keyPairInfo = cryptoTokenManagementSession.getKeyPairInfo(authenticationToken, cryptoTokenId, keyPairAlias);
            if (keyPairInfo == null) {
                if (cryptoTokenManagementSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId) == null) {
                    throw new CryptoTokenOfflineException("Unable to access keyPair with alias " + keyPairAlias + " in CryptoToken with id " + cryptoTokenId);
                }
            }
        }
        if (certificateId != null) {
            certificateId = certificateId.toLowerCase(Locale.ENGLISH);
        }
        // If we created a new InternalKeyBinding without a certificate reference (e.g. will be uploaded later) we will not allow the status to be anything but "DISABLED"
        if (certificateId == null || certificateStoreSession.findCertificateByFingerprint(certificateId) == null) {
            status = InternalKeyBindingStatus.DISABLED;
        }
        // Finally, try to create an instance of this type and persist it
        final InternalKeyBinding internalKeyBinding = InternalKeyBindingFactory.INSTANCE.create(type, id, name, status, certificateId, cryptoTokenId,
                keyPairAlias, initDataMap);
        internalKeyBinding.setSignatureAlgorithm(signatureAlgorithm);
        if (trustedCertificateReferences!=null) {
            internalKeyBinding.setTrustedCertificateReferences(trustedCertificateReferences);
        }
        if (StringUtils.isNotEmpty(issuerDn)) {
            internalKeyBinding.setSubjectDn(subjectDn);
            internalKeyBinding.setIssuerDn(issuerDn);
            internalKeyBinding.setCertificateProfileName(certificateProfileName);
            internalKeyBinding.setEndEntityProfileName(endEntityProfileName);
            internalKeyBinding.setKeySpec(keySpec);
        }
        final int allocatedId = internalKeyBindingDataSession.mergeInternalKeyBinding(internalKeyBinding);
        // Audit log the result after persistence (since the id generated during)
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", "Created InternalKeyBinding with id " + allocatedId);
        details.put("name", internalKeyBinding.getName());
        if (internalKeyBinding.getCertificateId()!=null) {
            details.put("certificateId", internalKeyBinding.getCertificateId());
        }
        details.put("keyPairAlias", internalKeyBinding.getKeyPairAlias());
        if (internalKeyBinding.getNextKeyPairAlias()!=null) {
            details.put("nextKeyPairAlias", internalKeyBinding.getNextKeyPairAlias());
        }
        details.put("signatureAlgorithm", internalKeyBinding.getSignatureAlgorithm());
        details.put("cryptoTokenId", String.valueOf(internalKeyBinding.getCryptoTokenId()));
        details.put("status", internalKeyBinding.getStatus().name());
        details.put("trustedCertificateReferences", Arrays.toString(internalKeyBinding.getTrustedCertificateReferences().toArray()));
        putDelta(new HashMap<>(), internalKeyBinding.getCopyOfProperties(), details);
        securityEventsLoggerSession.log(EventTypes.INTERNALKEYBINDING_CREATE, EventStatus.SUCCESS, ModuleTypes.INTERNALKEYBINDING, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(allocatedId), null, null, details);
        return allocatedId;
    }

    @Override
    public int createInternalKeyBinding(AuthenticationToken authenticationToken, String type, String name, InternalKeyBindingStatus status,
            String certificateId, int cryptoTokenId, String keyPairAlias, String signatureAlgorithm, Map<String, Serializable> dataMap,
            List<InternalKeyBindingTrustEntry> trustedCertificateReferences)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException, 
                InternalKeyBindingNonceConflictException {
        return createInternalKeyBinding(authenticationToken, type, 0, name, status, certificateId, cryptoTokenId, keyPairAlias, signatureAlgorithm,
                dataMap,trustedCertificateReferences);
    }

    @Override
    public int persistInternalKeyBinding(AuthenticationToken authenticationToken, InternalKeyBinding internalKeyBinding)
            throws AuthorizationDeniedException, InternalKeyBindingNameInUseException {
        if (!authorizationSession.isAuthorized(authenticationToken,
                InternalKeyBindingRules.MODIFY.resource() + "/" + internalKeyBinding.getId(), CryptoTokenRules.USE.resource() + "/"
                        + internalKeyBinding.getCryptoTokenId())) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.MODIFY.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        // Never allow activation of an InternalKeyBinding that has no certificate reference yet
        if (internalKeyBinding.getStatus().equals(InternalKeyBindingStatus.ACTIVE) && (internalKeyBinding.getCertificateId()==null
                || internalKeyBinding.getCertificateId().length()==0)) {
            internalKeyBinding.setStatus(InternalKeyBindingStatus.DISABLED);
            log.info("Preventing activation of Internal Key Binding " + internalKeyBinding.getId() + " since there is no certificate referenced.");
        }
        // Audit log the result before persistence
        final InternalKeyBinding originalInternalKeyBinding = internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBinding.getId());
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", "Edited InternalKeyBinding with id " + internalKeyBinding.getId());
        if (originalInternalKeyBinding.getName().equals(internalKeyBinding.getName())) {
            details.put("name", internalKeyBinding.getName());
        } else {
            putDelta("name", originalInternalKeyBinding.getName(), internalKeyBinding.getName(), details);
        }
        putDelta("certificateId", originalInternalKeyBinding.getCertificateId(), internalKeyBinding.getCertificateId(), details);
        putDelta("keyPairAlias", originalInternalKeyBinding.getKeyPairAlias(), internalKeyBinding.getKeyPairAlias(), details);
        putDelta("nextKeyPairAlias", originalInternalKeyBinding.getNextKeyPairAlias(), internalKeyBinding.getNextKeyPairAlias(), details);
        putDelta("signatureAlgorithm", originalInternalKeyBinding.getSignatureAlgorithm(), internalKeyBinding.getSignatureAlgorithm(), details);
        putDelta("cryptoTokenId", String.valueOf(originalInternalKeyBinding.getCryptoTokenId()), String.valueOf(internalKeyBinding.getCryptoTokenId()), details);
        putDelta("status", originalInternalKeyBinding.getStatus().name(), internalKeyBinding.getStatus().name(), details);
        putDelta("trustedCertificateReferences", 
                Arrays.toString(originalInternalKeyBinding.getTrustedCertificateReferences().toArray()), 
                Arrays.toString(internalKeyBinding.getTrustedCertificateReferences().toArray()), details);
        putDelta("signOcspResponseOnBehalf", 
                Arrays.toString(originalInternalKeyBinding.getSignOcspResponseOnBehalf().toArray()), 
                Arrays.toString(internalKeyBinding.getSignOcspResponseOnBehalf().toArray()), details);
        putDelta(originalInternalKeyBinding.getCopyOfProperties(), internalKeyBinding.getCopyOfProperties(), details);
        securityEventsLoggerSession.log(EventTypes.INTERNALKEYBINDING_EDIT, EventStatus.SUCCESS, ModuleTypes.INTERNALKEYBINDING, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(internalKeyBinding.getId()), null, null, details);
        return internalKeyBindingDataSession.mergeInternalKeyBinding(internalKeyBinding);
    }

    @Override
    public boolean deleteInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(authenticationToken, InternalKeyBindingRules.DELETE.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.DELETE.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        // Audit log the result before persistence
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBindingId);
        if (internalKeyBinding != null) {
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", "Deleted InternalKeyBinding with id " + internalKeyBinding.getId());
            details.put("name", internalKeyBinding.getName());
            securityEventsLoggerSession.log(EventTypes.INTERNALKEYBINDING_DELETE, EventStatus.SUCCESS, ModuleTypes.INTERNALKEYBINDING, ServiceTypes.CORE,
                    authenticationToken.toString(), String.valueOf(internalKeyBinding.getId()), null, null, details);
            return internalKeyBindingDataSession.removeInternalKeyBinding(internalKeyBindingId);
        } else {
            // Didn't exist
            return false;
        }
    }

    @Override
    public String generateNextKeyPair(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException,
            CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException {
        if (!authorizationSession.isAuthorized(authenticationToken, InternalKeyBindingRules.MODIFY.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.MODIFY.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBindingForEdit(internalKeyBindingId);
        final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        final String currentKeyPairAlias = internalKeyBinding.getKeyPairAlias();
        final String originalNextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
        internalKeyBinding.generateNextKeyPairAlias();
        final String nextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
        cryptoTokenManagementSession.createKeyPairWithSameKeySpec(authenticationToken, cryptoTokenId, currentKeyPairAlias, nextKeyPairAlias);
        try {
            // Audit log the result before persistence
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", "Modified next key pair for InternalKeyBinding with id " + internalKeyBinding.getId());
            details.put("name", internalKeyBinding.getName());
            details.put("cryptoTokenId", String.valueOf(internalKeyBinding.getCryptoTokenId()));
            putDelta("nextKeyPairAlias", originalNextKeyPairAlias, nextKeyPairAlias, details);
            securityEventsLoggerSession.log(EventTypes.INTERNALKEYBINDING_EDIT, EventStatus.SUCCESS, ModuleTypes.INTERNALKEYBINDING, ServiceTypes.CORE,
                    authenticationToken.toString(), String.valueOf(internalKeyBinding.getId()), null, null, details);
            internalKeyBindingDataSession.mergeInternalKeyBinding(internalKeyBinding);
        } catch (InternalKeyBindingNameInUseException e) {
            // This would be very strange if it happened, since we use the same name and id as for the existing one
            throw new RuntimeException(e);
        }
        return nextKeyPairAlias;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public byte[] getNextPublicKeyForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId)
            throws AuthorizationDeniedException, CryptoTokenOfflineException {
        if (!authorizationSession.isAuthorized(authenticationToken, InternalKeyBindingRules.VIEW.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.VIEW.resource(),
                    authenticationToken.toString());
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
        return cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, keyPairAlias).getPublicKey();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public byte[] generateCsrForNextKey(final AuthenticationToken authenticationToken, final int internalKeyBindingId, final byte[] name) throws AuthorizationDeniedException,
            CryptoTokenOfflineException {
        if (!authorizationSession.isAuthorized(authenticationToken, InternalKeyBindingRules.VIEW.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.VIEW.resource(),
                    authenticationToken.toString());
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
        final PublicKey publicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, keyPairAlias).getPublicKey();
        final String signatureAlgorithm = internalKeyBinding.getSignatureAlgorithm();
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(cryptoTokenId);
        final PrivateKey privateKey = cryptoToken.getPrivateKey(keyPairAlias);
        final X500Name x500Name;
        if (name != null) {
        	// If there was a parameter, use that
            x500Name = X500Name.getInstance(name);
        } else {
            // Try to look up the currently mapped certificates SubjectDN and use that
            final String fingerprint = internalKeyBinding.getCertificateId();
            if (fingerprint != null) {
                final Certificate certificate = certificateStoreSession.findCertificateByFingerprint(fingerprint);
                if (certificate != null) {
                    if (certificate instanceof X509Certificate) {
                        x500Name = X500Name.getInstance(((X509Certificate)certificate).getSubjectX500Principal().getEncoded());
                        if (log.isDebugEnabled()) {
                        	log.debug("Using subject DN from active X.509 certificate '" + x500Name.toString() + "'");
                        }
                    } else {
                        x500Name = DnComponents.stringToBcX500Name(CertTools.getSubjectDN(certificate));
                        if (log.isDebugEnabled()) {
                            log.debug("Using subject DN from active " + certificate.getType() +" certificate '" + x500Name.toString() + "'");
                        }
                    }
                } else {
                	// No mapped certificate exists, and no parameter, use default value
                    x500Name = DnComponents.stringToBcX500Name("CN="+internalKeyBinding.getName());                
                }
            } else {
                // No mapped certificate exists, and no parameter, use default value
                x500Name = DnComponents.stringToBcX500Name("CN="+internalKeyBinding.getName());                
            }
        }
        try {
            return internalKeyBinding.generateCsrForNextKeyPair(cryptoToken.getSignProviderName(), new KeyPair(publicKey, privateKey),
                    signatureAlgorithm, x500Name);
        } catch (OperatorCreationException | IOException | NoSuchAlgorithmException e) {
            log.info("CSR generation failed. internalKeyBindingId=" + internalKeyBindingId + ", cryptoTokenId=" + cryptoTokenId + ", keyPairAlias="
                    + keyPairAlias + ". " + e.getMessage());
            log.debug("CSR generation stack trace", e);
            return null;
        }
    }

    @Override
    public String updateCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId)
            throws AuthorizationDeniedException, CertificateImportException {
        if (!authorizationSession.isAuthorized(authenticationToken, InternalKeyBindingRules.MODIFY.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.MODIFY.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBindingForEdit(internalKeyBindingId);
        final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        final String originalNextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
        final String originalCertificateId = internalKeyBinding.getCertificateId();
        final String originalKeyPairAlias = internalKeyBinding.getKeyPairAlias();
        if (log.isDebugEnabled()) {
            log.debug("nextKeyPairAlias: " + originalNextKeyPairAlias);
        }
        boolean updated = false;
        if (originalNextKeyPairAlias != null) {
            // If a nextKeyPairAlias is present we assume that this is the one we want to find a certificate for
            PublicKey nextPublicKey;
            try {
                nextPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, originalNextKeyPairAlias).getPublicKey();
            } catch (CryptoTokenOfflineException e) {
                throw new CertificateImportException("Operation is not available when CryptoToken is offline.", e);
            }
            if (nextPublicKey != null) {
                final byte[] subjectKeyId = KeyTools.createSubjectKeyId(nextPublicKey).getKeyIdentifier();
                final Certificate certificate = certificateStoreSession.findMostRecentlyUpdatedActiveCertificate(subjectKeyId);
                if (certificate == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("No certificate found for " + originalNextKeyPairAlias);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Certificate found for " + originalNextKeyPairAlias);
                    }
                    // Verify that this is an accepted type of certificate to import for the current implementation
                    assertCertificateIsOkToImport(certificate, internalKeyBinding);
                    // If current key matches next public key -> import and update nextKey + certificateId
                    String fingerprint = CertTools.getFingerprintAsString(certificate);
                    if (!fingerprint.equals(originalCertificateId)) {
                        internalKeyBinding.updateCertificateIdAndCurrentKeyAlias(fingerprint);
                        updated = true;
                        if (log.isDebugEnabled()) {
                            log.debug("New certificate with fingerprint " + fingerprint + " matching " + originalNextKeyPairAlias + " will be used.");
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("The latest available certificate was already in use.");
                        }
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("There was no public key for the referenced alias " + originalNextKeyPairAlias);
                }
            }
        }
        if (!updated) {
            // We failed to find a matching certificate for the next key, so we instead try to do the same for the current key pair
            final String currentKeyPairAlias = internalKeyBinding.getKeyPairAlias();
            log.debug("currentKeyPairAlias: " + currentKeyPairAlias);
            PublicKey currentPublicKey;
            try {
                currentPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, currentKeyPairAlias).getPublicKey();
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
            // Audit log the result before persistence
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", "Updated certificate for InternalKeyBinding with id " + internalKeyBinding.getId());
            details.put("name", internalKeyBinding.getName());
            details.put("cryptoTokenId", String.valueOf(internalKeyBinding.getCryptoTokenId()));
            putDelta("certificateId", originalCertificateId, internalKeyBinding.getCertificateId(), details);
            putDelta("keyPairAlias", originalKeyPairAlias, internalKeyBinding.getKeyPairAlias(), details);
            putDelta("nextKeyPairAlias", originalNextKeyPairAlias, internalKeyBinding.getNextKeyPairAlias(), details);
            securityEventsLoggerSession.log(EventTypes.INTERNALKEYBINDING_EDIT, EventStatus.SUCCESS, ModuleTypes.INTERNALKEYBINDING, ServiceTypes.CORE,
                    authenticationToken.toString(), String.valueOf(internalKeyBinding.getId()), null, null, details);
            try {
                internalKeyBindingDataSession.mergeInternalKeyBinding(internalKeyBinding);
            } catch (InternalKeyBindingNameInUseException e) {
                // This would be very strange if it happened, since we use the same name and id as for the existing one
                throw new CertificateImportException(e);
            }
            if (log.isDebugEnabled()) {
                log.debug("No certificate found for " + originalNextKeyPairAlias);
            }
            return internalKeyBinding.getCertificateId();
        }
        return null;
    }

    @Override
    public boolean setStatus(AuthenticationToken authenticationToken, int internalKeyBindingId, InternalKeyBindingStatus status)
            throws AuthorizationDeniedException {
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
            throws AuthorizationDeniedException, CertificateImportException, InternalKeyBindingNonceConflictException {
        if (!authorizationSession.isAuthorized(authenticationToken, InternalKeyBindingRules.MODIFY.resource() + "/" + internalKeyBindingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", InternalKeyBindingRules.MODIFY.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        // UnDERify
        final Certificate certificate;
        try {
            certificate = CertTools.getCertfromByteArray(derEncodedCertificate, Certificate.class);
        } catch (CertificateException e) {
            throw new CertificateImportException(e);
        }
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBindingForEdit(internalKeyBindingId);        
        final String originalNextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
        final String originalCertificateId = internalKeyBinding.getCertificateId();
        final String originalKeyPairAlias = internalKeyBinding.getKeyPairAlias();
        // Verify that this is an accepted type of certificate to import for the current implementation
        assertCertificateIsOkToImport(certificate, internalKeyBinding);
        final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        if (log.isDebugEnabled()) {
            log.debug("certificate.getPublicKey(): "
                    + new String(Hex.encode(KeyTools.createSubjectKeyId(certificate.getPublicKey()).getKeyIdentifier())));
            log.debug("originalKeyPairAlias: " + originalKeyPairAlias);
        }
        boolean updated = false;
        try {
            String certificateId = CertTools.getFingerprintAsString(certificate);            
            checkForPreProductionAndNonceConflictBeforeImport(authenticationToken, internalKeyBinding, certificateId);            
            final PublicKey currentPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, originalKeyPairAlias).getPublicKey();
            if (log.isDebugEnabled()) {
                log.debug("currentPublicKey: "
                        + (currentPublicKey != null ? new String(Hex.encode(KeyTools.createSubjectKeyId(currentPublicKey).getKeyIdentifier()))
                                : "null"));
            }
            if (currentPublicKey != null
                    && KeyTools.createSubjectKeyId(currentPublicKey).equals(KeyTools.createSubjectKeyId(certificate.getPublicKey()))) {
                // If current key matches current public key -> import + update certificateId
                if (isCertificateAlreadyInDatabase(certificateId)) {
                    log.info("Certificate with fingerprint " + certificateId
                            + " was already present in the database. Only InternalKeyBinding reference will be updated.");
                } else {
                    storeCertificate(authenticationToken, internalKeyBinding, certificate);
                }
                internalKeyBinding.setCertificateId(certificateId);
                updated = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("originalNextKeyPairAlias: " + originalNextKeyPairAlias);
                }
                if (originalNextKeyPairAlias != null) {
                    final PublicKey nextPublicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, originalNextKeyPairAlias).getPublicKey();
                    if (log.isDebugEnabled()) {
                        log.debug("nextPublicKey: "
                                + (nextPublicKey != null ? new String(Hex.encode(KeyTools.createSubjectKeyId(nextPublicKey).getKeyIdentifier()))
                                        : "null"));
                    }
                    if (nextPublicKey != null
                            && KeyTools.createSubjectKeyId(nextPublicKey).equals(KeyTools.createSubjectKeyId(certificate.getPublicKey()))) {
                        // If current key matches next public key -> import and update nextKey + certificateId
                        if (isCertificateAlreadyInDatabase(certificateId)) {
                            log.info("Certificate with fingerprint " + certificateId
                                    + " was already present in the database. Only InternalKeyBinding reference will be updated.");
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
            // Audit log the result before persistence
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", "Edited InternalKeyBinding with id " + internalKeyBinding.getId());
            details.put("name", internalKeyBinding.getName());
            details.put("cryptoTokenId", String.valueOf(internalKeyBinding.getCryptoTokenId()));
            putDelta("certificateId", originalCertificateId, internalKeyBinding.getCertificateId(), details);
            putDelta("keyPairAlias", originalKeyPairAlias, internalKeyBinding.getKeyPairAlias(), details);
            putDelta("nextKeyPairAlias", originalNextKeyPairAlias, internalKeyBinding.getNextKeyPairAlias(), details);
            securityEventsLoggerSession.log(EventTypes.INTERNALKEYBINDING_EDIT, EventStatus.SUCCESS, ModuleTypes.INTERNALKEYBINDING, ServiceTypes.CORE,
                    authenticationToken.toString(), String.valueOf(internalKeyBinding.getId()), null, null, details);
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

    private void checkForPreProductionAndNonceConflictBeforeImport(AuthenticationToken authenticationToken, final InternalKeyBinding internalKeyBinding,
            String certificateId) throws InternalKeyBindingNonceConflictException {
        if ("OcspKeyBinding".equals(internalKeyBinding.getImplementationAlias())) {
            final DynamicUiProperty<? extends Serializable> nonceProperty = internalKeyBinding.getProperty("enableNonce");
            if (nonceProperty != null && "true".equals(nonceProperty.getValue().toString()) && certificateId != null) {
                final CertificateDataWrapper certificateDataWrapper = certificateStoreSession.getCertificateData(certificateId);
                if (certificateDataWrapper != null)  {
                    final CertificateData certificateData = certificateDataWrapper.getCertificateData();
                    final String caFingerprint = certificateData.getCaFingerprint();
                    if (caFingerprint != null) {
                        assertCaPreProductionNotUsed(authenticationToken, caFingerprint);
                    }
                }
            }
        }
    }

    private void assertCaPreProductionNotUsed(final AuthenticationToken authenticationToken, final String caFingerprint) throws InternalKeyBindingNonceConflictException {
        final CertificateDataWrapper caCertificateDataWrapper = certificateStoreSession.getCertificateData(caFingerprint);
        if (caCertificateDataWrapper != null)  {
            final Certificate caCertificate = caCertificateDataWrapper.getCertificate();
            final List<CAInfo> caInfos = caSession.getAuthorizedCaInfos(authenticationToken);
            for (CAInfo caInfo : caInfos) {
                if (CAInfo.CATYPE_X509 == caInfo.getCAType() && caInfo.getCertificateChain() != null && !caInfo.getCertificateChain().isEmpty()) {
                    final Certificate caCert = caInfo.getCertificateChain().get(0);
                    if (caCert.equals(caCertificate) && ((X509CAInfo)caInfo).isDoPreProduceOcspResponses()) {
                        throw new InternalKeyBindingNonceConflictException("Can not import certificate for OCSP Key Binding with nonce enabled in response when "
                                + "the associated CA has pre-production of OCSP responses enabled.");
                    }
                }
            }
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void issueCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId,
            EndEntityInformation endEntityInformation, String keySpec) 
                    throws AuthorizationDeniedException, CryptoTokenOfflineException, 
                            CertificateCreateException, CertificateImportException {
        // also generate the key if not present
        final InternalKeyBinding internalKeyBinding = internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBindingId);
        
        final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        final String keyPairAlias= internalKeyBinding.getKeyPairAlias();
        List<String> existingKeyPairs = cryptoTokenManagementSession.getKeyPairAliases(authenticationToken, cryptoTokenId);
        if(!existingKeyPairs.contains(keyPairAlias)) {
            try {
                // same publicKey spec as CA - inline with OCSP RFCs
                if (keySpec == null) {
                    if (StringUtils.isNotEmpty(internalKeyBinding.getKeySpec())) {
                        keySpec = internalKeyBinding.getKeySpec();
                    } else {
                        final PublicKey caPublicKey = caSession.findById(
                                endEntityInformation.getCAId()).getCA().getCACertificate().getPublicKey();
                        keySpec = AlgorithmTools.getKeySpecification(caPublicKey);
                    }
                }
                final KeyPairTemplate keyUsage = KeyPairTemplate.valueOf(KeyPairTemplate.SIGN.toString());
                final KeyGenParamsBuilder paramBuilder = KeyGenParams.builder(keySpec).withKeyPairTemplate(keyUsage);
                cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, keyPairAlias, paramBuilder.build());
            } catch (InvalidKeyException | CryptoTokenOfflineException | 
                            InvalidAlgorithmParameterException | AuthorizationDeniedException e) {
                log.error("Failed to create keypair fo key binding", e);
                throw new CertificateCreateException("Failed to create keypair fo key binding");
            }
        }
        
        final PublicKey publicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, keyPairAlias).getPublicKey();
        final RequestMessage req = new SimpleRequestMessage(publicKey, endEntityInformation.getUsername(), endEntityInformation.getPassword());
        final CertificateResponseMessage response;
        final long updateTime = System.currentTimeMillis();
        try {
            response = certificateCreateSession.createCertificate(authenticationToken, endEntityInformation, req, X509ResponseMessage.class, new CertificateGenerationParams(), updateTime);
        } catch (CesecoreException | CertificateExtensionException e) {
            throw new CertificateCreateException(e);
        }
        final String newCertificateId = updateCertificateForInternalKeyBinding(authenticationToken, internalKeyBindingId);
        if (newCertificateId == null) {
            throw new CertificateCreateException("New certificate was never issued.");
        }
        setStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
        // Sanity check that the certificate we issued is the one that is in use
        final X509Certificate keyBindingCertificate = (X509Certificate) response.getCertificate();
        if (!newCertificateId.equals(CertTools.getFingerprintAsString(keyBindingCertificate))) {
            throw new CertificateCreateException(
                    "Issued certificate was not found in database. "
                    + "Throw-away setting for issuing CA is not allowed for InternalKeyBindings.");
        }

    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public String renewInternallyIssuedCertificate(AuthenticationToken authenticationToken, int internalKeyBindingId,
            EndEntityInformation endEntityInformation) throws AuthorizationDeniedException, CryptoTokenOfflineException, CertificateImportException {
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
        final long updateTime = System.currentTimeMillis();
        try {
            response = certificateCreateSession.createCertificate(authenticationToken, endEntityInformation, req, X509ResponseMessage.class, new CertificateGenerationParams(), updateTime);
        } catch (CesecoreException | CertificateExtensionException e) {
            throw new CertificateImportException(e);
        }
        final String newCertificateId = updateCertificateForInternalKeyBinding(authenticationToken, internalKeyBindingId);
        if (newCertificateId == null) {
            throw new CertificateImportException("New certificate was never issued.");
        }
        // Sanity check that the certificate we issued is the one that is in use
        final X509Certificate keyBindingCertificate = (X509Certificate) response.getCertificate();
        if (!newCertificateId.equals(CertTools.getFingerprintAsString(keyBindingCertificate))) {
            throw new CertificateImportException(
                    "Issued certificate was not found in database. Throw-away setting for issuing CA is not allowed for InternalKeyBindings.");
        }
        return newCertificateId;
    }

    private void assertAuthorization(AuthenticationToken authenticationToken, final String... rules) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(authenticationToken, rules)) {
            if (rules.length == 1) {
                final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", rules[0], authenticationToken.toString());
                throw new AuthorizationDeniedException(msg);
            } else {
                final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", Arrays.toString(rules),
                        authenticationToken.toString());
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
        internalKeyBinding.assertCertificateCompatability(certificate, 
                (AvailableExtendedKeyUsagesConfiguration) globalConfigurationSession.getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID));
    }

    /** @return true if a certificate with the specified certificateId (fingerprint) already exists in the database */
    private boolean isCertificateAlreadyInDatabase(String certificateId) {
        return certificateStoreSession.findCertificateByFingerprint(certificateId) != null;
    }

    /** Imports the certificate to the database */
    private void storeCertificate(AuthenticationToken authenticationToken, InternalKeyBinding internalKeyBinding, Certificate certificate)
            throws AuthorizationDeniedException, CertificateImportException {
        // First check if the certificate row has been published without the actual certificate
        // if so, we only need to import the actual certificate
        if (certificateStoreSession.updateCertificateOnly(authenticationToken, certificate)) {
            return;
        }
        // Set some values for things we cannot know
        final String username = "IMPORTED_InternalKeyBinding_" + internalKeyBinding.getId();
        // Find caFingerprint through ca(Admin?)Session
        final List<Integer> availableCaIds = caSession.getAuthorizedCaIds(authenticationToken);
        final String issuerDn = CertTools.getIssuerDN(certificate);
        /*
         * Algorithm:
         * - Find current CA with a certificate with a SubjectDN matching the IssuerDN of the leaf cert.
         * - If found, check if the current CA certificate can verify the leaf cert's signature.
         * - If this key didn't sign the leaf certificate, find the latest issued CA certificate with the CA's SubjectDN that can verify the leaf cert.
         */
        String caFingerprint = null;
        for (final Integer caId : availableCaIds) {
            try {
                final Certificate caCert = caSession.getCAInfo(authenticationToken, caId).getCertificateChain().iterator().next();
                final String subjectDn = CertTools.getSubjectDN(caCert);
                if (subjectDn.equals(issuerDn)) {
                    try {
                        certificate.verify(caCert.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
                        caFingerprint = CertTools.getFingerprintAsString(caCert);
                    } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                        if (log.isDebugEnabled()) {
                            log.debug("Unable to verify IKB certificate to import using current CA certificate with serialnumber " +
                                    CertTools.getSerialNumber(caCert) + " (0x"+CertTools.getSerialNumberAsString(caCert)+"): " + e.getMessage());
                        }
                        // Since there exists a CA on this system with the correct issuer, this might be for a previous version of this CA using a different key
                        final List<Certificate> potentialCaCerts = certificateStoreSession.findCertificatesBySubject(issuerDn);
                        potentialCaCerts.remove(caCert);
                        for (final Certificate potentialCaCert : new ArrayList<>(potentialCaCerts)) {
                            if (!CertTools.isCA(potentialCaCert)) {
                                potentialCaCerts.remove(potentialCaCert);
                                continue;
                            }
                            try {
                                certificate.verify(potentialCaCert.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
                            } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e1) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Unable to verify IKB certificate to import using CA certificate with serialnumber " +
                                            CertTools.getSerialNumber(potentialCaCert) + " (0x"+CertTools.getSerialNumberAsString(potentialCaCert)+"): " + e1.getMessage());
                                }
                                potentialCaCerts.remove(potentialCaCert);
                            }
                        }
                        if (!potentialCaCerts.isEmpty()) {
                            // Sort by notBefore descending and to use the latest issued (newest notBefore)
                            potentialCaCerts.sort((o1, o2) -> CertTools.getNotBefore(o2).compareTo(CertTools.getNotBefore(o1)));
                            final Certificate choosenCaCert = potentialCaCerts.get(0);
                            log.info("Able to verify IKB certificate to import using CA certificate with serialnumber " +
                                    CertTools.getSerialNumber(choosenCaCert) + " (0x"+CertTools.getSerialNumberAsString(choosenCaCert)+").");
                            caFingerprint = CertTools.getFingerprintAsString(choosenCaCert);
                        }
                    }
                    // No need to check other CAs even if the right CA cert was not found
                    break;
                }
            } catch (NoSuchElementException e) {
                log.debug("CA with caId " + caId + " has no certificate chain.");
            }
        }
        if (caFingerprint == null) {
            throw new CertificateImportException("No CA certificate for " + issuerDn
                    + " was found on the system. You must import the CA as an external CA before activating the internal key binding.");
        }
        certificateStoreSession.storeCertificate(authenticationToken, certificate, username, caFingerprint, CertificateConstants.CERT_ACTIVE,
                CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.NO_CERTIFICATE_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE,
                CertificateConstants.NO_CRL_PARTITION, null, System.currentTimeMillis(), null);
    }

    /** Helper method for audit logging changes */
    private void putDelta(final Map<String, DynamicUiProperty<? extends Serializable>> oldProperties, final Map<String, DynamicUiProperty<? extends Serializable>> newProperties,
            final Map<String, Object> details) {
        // Find out what has happended to all the old properties
        for (final String key : oldProperties.keySet()) {
            final DynamicUiProperty<? extends Serializable> oldValue = oldProperties.get(key);
            final DynamicUiProperty<? extends Serializable> newValue = newProperties.get(key);
            putDelta(key, getAsStringValue(oldValue), getAsStringValue(newValue), details);
        }
        // Find out which new properties that did not exist in the old
        for (final String key : newProperties.keySet()) {
            final DynamicUiProperty<? extends Serializable> oldValue = oldProperties.get(key);
            if (oldValue==null) {
                final DynamicUiProperty<? extends Serializable> newValue = newProperties.get(key);
                putDelta(key, getAsStringValue(oldValue), getAsStringValue(newValue), details);
            }
        }
    }

    /** Helper method for audit logging changes */
    private void putDelta(final String key, final String oldValue, final String newValue, final Map<String, Object> details) {
        if (oldValue != null || newValue != null) {
            if (oldValue == null) {
                details.put("added:" + key, newValue);
            } else if (newValue == null) {
                details.put("removed:" + key, oldValue);
            } else if (!oldValue.equals(newValue)) {
                details.put("changed:" + key, newValue);
            }
        }
    }
    
    private String getAsStringValue(final DynamicUiProperty<? extends Serializable> valueObj) {
        if (valueObj!=null && valueObj.getValue()!=null) {
            return String.valueOf(valueObj.getValue());
        }
        return null;
    }
}
