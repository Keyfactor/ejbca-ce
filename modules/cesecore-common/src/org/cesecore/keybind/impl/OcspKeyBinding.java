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

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingBase;
import org.cesecore.util.CertTools;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Holder of "external" (e.g. non-CA signing key) OCSP InternalKeyBinding properties.
 * 
 * @version $Id$
 */
public class OcspKeyBinding extends InternalKeyBindingBase {
  
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(OcspKeyBinding.class);
    
    public enum ResponderIdType {
        KEYHASH(2, "KeyHash"), NAME(1, "Name");
        
        private final int numericValue;
        private final String label;
        private static Map<Integer, ResponderIdType> numericValueLookupMap;
        
        static {
            numericValueLookupMap = new HashMap<>();
            for(ResponderIdType responderIdType : ResponderIdType.values()) {
                numericValueLookupMap.put(responderIdType.getNumericValue(), responderIdType);
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
            return numericValueLookupMap.get(Integer.valueOf(numericValue));
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
    
    {
        addProperty(new DynamicUiProperty<Boolean>(PROPERTY_NON_EXISTING_GOOD, Boolean.FALSE));
        addProperty(new DynamicUiProperty<Boolean>(PROPERTY_NON_EXISTING_REVOKED, Boolean.FALSE));
        addProperty(new DynamicUiProperty<Boolean>(PROPERTY_NON_EXISTING_UNAUTHORIZED, Boolean.FALSE));
        addProperty(new DynamicUiProperty<Boolean>(PROPERTY_INCLUDE_CERT_CHAIN, Boolean.TRUE));
        addProperty(new DynamicUiProperty<Boolean>(PROPERTY_INCLUDE_SIGN_CERT, Boolean.TRUE));
        addProperty(new DynamicUiProperty<String>(PROPERTY_RESPONDER_ID_TYPE, ResponderIdType.KEYHASH.name(),
                Arrays.asList(ResponderIdType.KEYHASH.name(), ResponderIdType.NAME.name())));
        addProperty(new DynamicUiProperty<Boolean>(PROPERTY_REQUIRE_TRUSTED_SIGNATURE, Boolean.FALSE));
        addProperty(new DynamicUiProperty<Long>(PROPERTY_UNTIL_NEXT_UPDATE, Long.valueOf(0L)));
        addProperty(new DynamicUiProperty<Long>(PROPERTY_MAX_AGE, Long.valueOf(0L)));
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
        setProperty(PROPERTY_NON_EXISTING_GOOD, Boolean.valueOf(nonExistingGood));
    }
    public boolean getNonExistingRevoked() {
        return (Boolean) getProperty(PROPERTY_NON_EXISTING_REVOKED).getValue();
    }
    public void setNonExistingRevoked(boolean nonExistingRevoked) {
        setProperty(PROPERTY_NON_EXISTING_REVOKED, Boolean.valueOf(nonExistingRevoked));
    }
    public boolean getNonExistingUnauthorized() {
        if(getProperty(PROPERTY_NON_EXISTING_UNAUTHORIZED) == null) {
            setNonExistingUnauthorized(false);
        }
        return (Boolean) getProperty(PROPERTY_NON_EXISTING_UNAUTHORIZED).getValue();
    }
    public void setNonExistingUnauthorized(boolean nonExistingUnauthorized) {
        setProperty(PROPERTY_NON_EXISTING_UNAUTHORIZED, Boolean.valueOf(nonExistingUnauthorized));
    }
    public boolean getIncludeCertChain() {
        return (Boolean) getProperty(PROPERTY_INCLUDE_CERT_CHAIN).getValue();
    }
    public void setIncludeCertChain(boolean includeCertChain) {
        setProperty(PROPERTY_INCLUDE_CERT_CHAIN, Boolean.valueOf(includeCertChain));
    }
    public boolean getIncludeSignCert() {
        return (Boolean) getProperty(PROPERTY_INCLUDE_SIGN_CERT).getValue();
    }
    public void setIncludeSignCert(boolean includeCertChain) {
        setProperty(PROPERTY_INCLUDE_SIGN_CERT, Boolean.valueOf(includeCertChain));
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
        setProperty(PROPERTY_REQUIRE_TRUSTED_SIGNATURE, Boolean.valueOf(requireTrustedSignature));
    }
    /** @return the value in seconds (granularity defined in RFC 5019) */
    public long getUntilNextUpdate() {
        return (Long) getProperty(PROPERTY_UNTIL_NEXT_UPDATE).getValue();
    }
    /** Set the value in seconds (granularity defined in RFC 5019) */
    public void setUntilNextUpdate(long untilNextUpdate) {
        setProperty(PROPERTY_UNTIL_NEXT_UPDATE, Long.valueOf(untilNextUpdate));
    }
    /** @return the value in seconds (granularity defined in RFC 5019) */
    public long getMaxAge() {
        return (Long) getProperty(PROPERTY_MAX_AGE).getValue();
    }
    /** Set the value in seconds (granularity defined in RFC 5019) */
    public void setMaxAge(long maxAge) {
        setProperty(PROPERTY_MAX_AGE, Long.valueOf(maxAge));
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
            if (!x509Certificate.getKeyUsage()[0] && !x509Certificate.getKeyUsage()[1] ) {
                throw new CertificateImportException("Key Usage digitalSignature is required (nonRepudiation would also be accepted).");
            }
        } catch (CertificateParsingException e) {
            throw new CertificateImportException(e.getMessage(), e);
        }
    }
}
