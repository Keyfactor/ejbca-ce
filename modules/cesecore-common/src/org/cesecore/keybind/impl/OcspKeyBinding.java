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

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingBase;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.ui.DynamicUiProperty;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Holder of "external" (e.g. non-CA signing key) OCSP InternalKeyBinding properties.
 */
public class OcspKeyBinding extends InternalKeyBindingBase {
  
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(OcspKeyBinding.class);

    public enum ResponderIdType {
        KEYHASH(2, "KeyHash"), NAME(1, "Name");
        
        private final int numericValue;
        private final String label;
        private static Map<Integer, ResponderIdType> numericValueLookupMap = new HashMap<>();
        private static Map<String, ResponderIdType> labelLookupMap = new HashMap<>();
        
        static {
            for (ResponderIdType responderIdType : ResponderIdType.values()) {
                numericValueLookupMap.put(responderIdType.getNumericValue(), responderIdType);
                labelLookupMap.put(responderIdType.getLabel(), responderIdType);
            }
        }
        
        private ResponderIdType(int numericValue, String label) {
            this.numericValue = numericValue;
            this.label = label;
        }
        
        public int getNumericValue() {
            return numericValue;
        }
        
        public String getLabel() {
            return label;
        }
        
        public static ResponderIdType getFromNumericValue(int numericValue) {
            return numericValueLookupMap.get(numericValue);
        }
        
        public static ResponderIdType getFromLabel(final String label) {
            return labelLookupMap.get(label);
        }

    }

    public static final String IMPLEMENTATION_ALIAS = "OcspKeyBinding"; // This should not change, even if we rename the class in EJBCA 5.3+..
    public static final String PROPERTY_NON_EXISTING_GOOD = "nonexistingisgood";
    public static final String PROPERTY_NON_EXISTING_REVOKED = "nonexistingisrevoked";
    public static final String PROPERTY_NON_EXISTING_UNAUTHORIZED = "nonexistingisunauthorized";
    public static final String PROPERTY_INCLUDE_CERT_CHAIN = "includecertchain";
    public static final String PROPERTY_INCLUDE_SIGN_CERT = "includesigncert";
    public static final String PROPERTY_RESPONDER_ID_TYPE = "responderidtype";  // keyhash, name
    public static final String PROPERTY_REQUIRE_TRUSTED_SIGNATURE = "requireTrustedSignature";
    public static final String PROPERTY_UNTIL_NEXT_UPDATE = "untilNextUpdate";
    public static final String PROPERTY_MAX_AGE = "maxAge";
    public static final String PROPERTY_ENABLE_NONCE = "enableNonce";
    public static final String PROPERTY_OMIT_REASON_CODE_WHEN_REVOCATION_REASON_UNSPECIFIED = "omitreasoncodewhenrevocationreasonunspecified"; 
    public static final String PROPERTY_USE_ISSUER_NOTBEFORE_AS_ARCHIVE_CUTOFF = "useIssuerNotBeforeAsArchiveCutoff";
    public static final String PROPERTY_RETENTION_PERIOD = "retentionPeriod";
    
    {
        addProperty(new DynamicUiProperty<>(PROPERTY_NON_EXISTING_GOOD, Boolean.FALSE));
        addProperty(new DynamicUiProperty<>(PROPERTY_NON_EXISTING_REVOKED, Boolean.FALSE));
        addProperty(new DynamicUiProperty<>(PROPERTY_NON_EXISTING_UNAUTHORIZED, Boolean.FALSE));
        addProperty(new DynamicUiProperty<>(PROPERTY_INCLUDE_CERT_CHAIN, Boolean.TRUE));
        addProperty(new DynamicUiProperty<>(PROPERTY_INCLUDE_SIGN_CERT, Boolean.TRUE));
        addProperty(new DynamicUiProperty<>(PROPERTY_RESPONDER_ID_TYPE, ResponderIdType.KEYHASH.name(),
                Arrays.asList(ResponderIdType.KEYHASH.name(), ResponderIdType.NAME.name())));
        addProperty(new DynamicUiProperty<>(PROPERTY_REQUIRE_TRUSTED_SIGNATURE, Boolean.FALSE));
        addProperty(new DynamicUiProperty<>(PROPERTY_UNTIL_NEXT_UPDATE, 0L));
        addProperty(new DynamicUiProperty<>(PROPERTY_MAX_AGE, 0L));
        addProperty(new DynamicUiProperty<>(PROPERTY_ENABLE_NONCE, Boolean.TRUE));
        addProperty(new DynamicUiProperty<>(PROPERTY_OMIT_REASON_CODE_WHEN_REVOCATION_REASON_UNSPECIFIED, Boolean.TRUE));

    }

    
    @Override
    public String getImplementationAlias() {
        return IMPLEMENTATION_ALIAS;
    }
    
    @Override
    public float getLatestVersion() {
        return serialVersionUID;
    }

    @Override
    protected void upgrade(float latestVersion, float currentVersion) {
        // Nothing to do
    }
    
    @Override
    public void assertCertificateCompatability(final Certificate certificate, final AvailableExtendedKeyUsagesConfiguration ekuConfig) throws CertificateImportException {
        assertCertificateCompatabilityInternal(certificate, ekuConfig);
    }

    public boolean getNonExistingGood() {
        return (Boolean) getProperty(PROPERTY_NON_EXISTING_GOOD).getValue();
    }
    public void setNonExistingGood(boolean nonExistingGood) {
        setProperty(PROPERTY_NON_EXISTING_GOOD, nonExistingGood);
    }
    public boolean getNonExistingRevoked() {
        return (Boolean) getProperty(PROPERTY_NON_EXISTING_REVOKED).getValue();
    }
    public void setNonExistingRevoked(boolean nonExistingRevoked) {
        setProperty(PROPERTY_NON_EXISTING_REVOKED, nonExistingRevoked);
    }
    public boolean getNonExistingUnauthorized() {
        if(getProperty(PROPERTY_NON_EXISTING_UNAUTHORIZED) == null) {
            setNonExistingUnauthorized(false);
        }
        return (Boolean) getProperty(PROPERTY_NON_EXISTING_UNAUTHORIZED).getValue();
    }
    public void setNonExistingUnauthorized(boolean nonExistingUnauthorized) {
        setProperty(PROPERTY_NON_EXISTING_UNAUTHORIZED, nonExistingUnauthorized);
    }
    public boolean getIncludeCertChain() {
        return (Boolean) getProperty(PROPERTY_INCLUDE_CERT_CHAIN).getValue();
    }
    public void setIncludeCertChain(boolean includeCertChain) {
        setProperty(PROPERTY_INCLUDE_CERT_CHAIN, includeCertChain);
    }
    public boolean getIncludeSignCert() {
        return (Boolean) getProperty(PROPERTY_INCLUDE_SIGN_CERT).getValue();
    }
    public void setIncludeSignCert(boolean includeCertChain) {
        setProperty(PROPERTY_INCLUDE_SIGN_CERT, includeCertChain);
    }
    public ResponderIdType getResponderIdType() {
        return ResponderIdType.valueOf((String) getProperty(PROPERTY_RESPONDER_ID_TYPE).getValue());
    }
    public void setResponderIdType(ResponderIdType responderIdType) {
        setProperty(PROPERTY_RESPONDER_ID_TYPE, responderIdType.name());
    }
    public boolean getRequireTrustedSignature() {
        return (Boolean) getProperty(PROPERTY_REQUIRE_TRUSTED_SIGNATURE).getValue();
    }
    public void setRequireTrustedSignature(boolean requireTrustedSignature) {
        setProperty(PROPERTY_REQUIRE_TRUSTED_SIGNATURE, requireTrustedSignature);
    }
    /** @return the value in seconds (granularity defined in RFC 5019) */
    public long getUntilNextUpdate() {
        return (Long) getProperty(PROPERTY_UNTIL_NEXT_UPDATE).getValue();
    }
    /** Set the value in seconds (granularity defined in RFC 5019) */
    public void setUntilNextUpdate(long untilNextUpdate) {
        setProperty(PROPERTY_UNTIL_NEXT_UPDATE, untilNextUpdate);
    }
    /** @return the value in seconds (granularity defined in RFC 5019) */
    public long getMaxAge() {
        return (Long) getProperty(PROPERTY_MAX_AGE).getValue();
    }
    /** Set the value in seconds (granularity defined in RFC 5019) */
    public void setMaxAge(long maxAge) {
        setProperty(PROPERTY_MAX_AGE, maxAge);
    }
    
    /** @return true if NONCE's are to be used in replies */
    public boolean isNonceEnabled() {
        if(getProperty(PROPERTY_ENABLE_NONCE) == null) {
            setNonceEnabled(true);
        }
        return (Boolean) getProperty(PROPERTY_ENABLE_NONCE).getValue();
    }
    /** 
     * @param enabled as true of NONCE's are to be included in replies
     *  */
    public void setNonceEnabled(boolean enabled) {
        setProperty(PROPERTY_ENABLE_NONCE, enabled);
    }
    
    /** @return true if the revocation reason to be omitted if specified */
    public boolean isOmitReasonCodeEnabled() {
        if(getProperty(PROPERTY_OMIT_REASON_CODE_WHEN_REVOCATION_REASON_UNSPECIFIED) == null) {
            setNonceEnabled(true);
        }
        return (Boolean) getProperty(PROPERTY_OMIT_REASON_CODE_WHEN_REVOCATION_REASON_UNSPECIFIED).getValue();
    }

    public void setOmitReasonCodeEnabled(boolean enabled) {
        setProperty(PROPERTY_OMIT_REASON_CODE_WHEN_REVOCATION_REASON_UNSPECIFIED, enabled);
    }
    
    /** Helper method to check if the OCSP Archive CutOff extension is enabled. Used by Configdump */
    public boolean isOcspArchiveCutOffExtensionEnabled() {
        return getOcspExtensions().stream().anyMatch(enabledOcspExtension -> OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId().equals(enabledOcspExtension));
    }

    /**
     * Get the retention period being enforced by the CA. The date obtained by subtracting this
     * retention interval value from the producedAt time in a response is defined as the 
     * certificate's "archive cutoff" date.
     * 
     * <p>If nothing is specified for this OCSP key binding, the default value of 1 year is used.
     * 
     * @return the retention period for archive cutoff.
     */
    public SimpleTime getRetentionPeriod() {
        final String retentionPeriod = getData(PROPERTY_RETENTION_PERIOD, "1y");
        return SimpleTime.getInstance(retentionPeriod);
    }

    /**
     * Set the retention period being enforced by the CA. See also {@link #getRetentionPeriod()}.
     * 
     * @param retentionPeriod the new retention period to use for archive cutoff.
     */
    public void setRetentionPeriod(final SimpleTime retentionPeriod) {
        putData(PROPERTY_RETENTION_PERIOD, retentionPeriod.toString());
    }

    /**
     * Get a boolean indicating whether the notBefore date of the issuer of the certificate being queried for,
     * should be used as archive cutoff date in OCSP responses, when the archiveCutoff extension is enabled
     * (instead of deriving the archive cutoff date from the producedAt time of the OCSP response).
     * 
     * <p>This setting should be enabled to conform with ETSI EN 319 411-2, CSS-6.3.10-08.
     * 
     * <p>If nothing is specified for this OCSP key binding, the default value of false is returned
     * (do not use the issuer's notBefore date as archive cutoff date).
     *  
     * @return true if the responder is using ETSI compliant archive cutoff dates.
     */
    public boolean getUseIssuerNotBeforeAsArchiveCutoff() {
        return getData(PROPERTY_USE_ISSUER_NOTBEFORE_AS_ARCHIVE_CUTOFF, false);
    }

    /**
     * Set a boolean indicating whether the notBefore date of the issuer of the certificate being queried for,
     * should be used as archive cutoff date in OCSP responses, when the archiveCutoff extension is enabled.
     * See also {@link #getUseIssuerNotBeforeAsArchiveCutoff()}.
     * 
     * @param useIssuerNotBeforeAsArchiveCutoff true to enable this setting, false otherwise.
     */
    public void setUseIssuerNotBeforeAsArchiveCutoff(final boolean useIssuerNotBeforeAsArchiveCutoff) {
        putData(PROPERTY_USE_ISSUER_NOTBEFORE_AS_ARCHIVE_CUTOFF, useIssuerNotBeforeAsArchiveCutoff);
    }

    public static boolean isOcspSigningCertificate(final Certificate certificate, AvailableExtendedKeyUsagesConfiguration ekuConfig) {
        try {
            assertCertificateCompatabilityInternal(certificate, ekuConfig);
        } catch (CertificateImportException e) {
            return false;
        }
        return true;
    }

    private static void assertCertificateCompatabilityInternal(final Certificate certificate, AvailableExtendedKeyUsagesConfiguration ekuConfig) throws CertificateImportException {
        if (certificate == null) {
            throw new CertificateImportException("No certificate provided.");
        }
        if (!(certificate instanceof X509Certificate)) {
            throw new CertificateImportException("Only X509 certificates are supported for OCSP.");
        }
        try {
            final X509Certificate x509Certificate = (X509Certificate) certificate;
            if (log.isDebugEnabled()) {
                log.debug("SubjectDN: " + CertTools.getSubjectDN(x509Certificate) + " IssuerDN: " + CertTools.getIssuerDN(x509Certificate));
                final boolean[] ku = x509Certificate.getKeyUsage();
                log.debug("Key usages: " + Arrays.toString(ku));
                if (ku != null) {
                    log.debug("Key usage (digitalSignature): " + x509Certificate.getKeyUsage()[0]);
                    log.debug("Key usage (nonRepudiation):   " + x509Certificate.getKeyUsage()[1]);
                    log.debug("Key usage (keyEncipherment):  " + x509Certificate.getKeyUsage()[2]);
                }
            }
            if (x509Certificate.getExtendedKeyUsage() == null) {
                throw new CertificateImportException("No Extended Key Usage present in certificate.");
            }
            for (String extendedKeyUsage : x509Certificate.getExtendedKeyUsage()) {
                log.debug("EKU: " + extendedKeyUsage + " (" +
                        ekuConfig.getAllEKUOidsAndNames().get(extendedKeyUsage) + ")");
            }
            if (!x509Certificate.getExtendedKeyUsage().contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
                throw new CertificateImportException("Extended Key Usage 1.3.6.1.5.5.7.3.9 (EKU_PKIX_OCSPSIGNING) is required.");
            }
            if (x509Certificate.getKeyUsage() != null && !x509Certificate.getKeyUsage()[0] && !x509Certificate.getKeyUsage()[1] ) {
                throw new CertificateImportException("Key Usage digitalSignature is required (nonRepudiation would also be accepted).");
            }
        } catch (CertificateParsingException e) {
            throw new CertificateImportException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] generateCsrForNextKeyPair(final String providerName, final KeyPair keyPair, final String signatureAlgorithm,
            final X500Name subjectDn) throws IOException, NoSuchAlgorithmException, OperatorCreationException {
        final KeyPurposeId[] ocspKeyPurposeId = new KeyPurposeId[] { KeyPurposeId.id_kp_OCSPSigning };
        final SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils()
                .createSubjectKeyIdentifier(keyPair.getPublic());

        final ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, /* critical */ false, subjectKeyIdentifier);
        extensionsGenerator.addExtension(Extension.keyUsage, /* critical */ true, new KeyUsage(KeyUsage.digitalSignature));
        extensionsGenerator.addExtension(Extension.extendedKeyUsage, /* critical */ false, new ExtendedKeyUsage(ocspKeyPurposeId));
        extensionsGenerator.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, /* critical */ false, DERNull.INSTANCE);

        final PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(subjectDn,
                keyPair.getPublic()).addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        final String prov;
        if (BouncyCastleProvider.PROVIDER_NAME.equals(providerName)) {
            // Ability to use the PQC provider
            prov = CryptoProviderTools.getProviderNameFromAlg(signatureAlgorithm);
        } else {
            prov = providerName;
        }
        final ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(prov).build(keyPair.getPrivate());
        final PKCS10CertificationRequest csr = pkcs10CertificationRequestBuilder.build(contentSigner);
        return csr.getEncoded();
    }
}
