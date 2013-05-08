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
package org.ejbca.core.ejb.keybind.impl;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.cesecore.config.ExtendedKeyUsageConfiguration;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.keybind.CertificateImportException;
import org.ejbca.core.ejb.keybind.InternalKeyBindingBase;
import org.ejbca.core.ejb.keybind.InternalKeyBindingProperty;

/**
 * Holder of "external" (e.g. non-CA signing key) OCSP InternalKeyBinding properties.
 * 
 * @version $Id$
 */
public class OcspKeyBinding extends InternalKeyBindingBase {
  
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(OcspKeyBinding.class);
    
    public enum ResponderIdType {
        KEYHASH, NAME;
    }

    public static final String IMPLEMENTATION_ALIAS = "OcspKeyBinding"; // This should not change, even if we rename the class in EJBCA 5.3+..
    public static final String PROPERTY_NON_EXISTING_GOOD = "nonexistingisgood";
    public static final String PROPERTY_INCLUDE_CERT_CHAIN = "includecertchain";
    public static final String PROPERTY_RESPONDER_ID_TYPE = "responderidtype";  // keyhash, name
    public static final String PROPERTY_REQUIRE_TRUSTED_SIGNATURE = "requireTrustedSignature";
    public static final String PROPERTY_UNTIL_NEXT_UPDATE = "untilNextUpdate";
    public static final String PROPERTY_MAX_AGE = "maxAge";
    //signaturealgorithm -> base class
    //signaturerequired, false -> PROPERTY_REQUIRE_TRUSTED_SIGNATURE + empty trust list
    //restrictsignaturesbyissuer, false -> PROPERTY_REQUIRE_TRUSTED_SIGNATURE + trust list
    //restrictsignaturesbysigner, false -> PROPERTY_REQUIRE_TRUSTED_SIGNATURE + trust list
    //untilNextUpdate, 0, -> per cert profile still in config file, if set here it would override global but not per cert profile setting
    //maxAge, 30 -> as untilNextUpdate
    
    @SuppressWarnings("serial")
    public OcspKeyBinding() {
        super(new ArrayList<InternalKeyBindingProperty<? extends Serializable>>() {{
            add(new InternalKeyBindingProperty<Boolean>(PROPERTY_NON_EXISTING_GOOD, Boolean.FALSE));
            add(new InternalKeyBindingProperty<Boolean>(PROPERTY_INCLUDE_CERT_CHAIN, Boolean.TRUE));
            add(new InternalKeyBindingProperty<String>(PROPERTY_RESPONDER_ID_TYPE, ResponderIdType.KEYHASH.name(), ResponderIdType.KEYHASH.name(), ResponderIdType.NAME.name()));
            add(new InternalKeyBindingProperty<Boolean>(PROPERTY_REQUIRE_TRUSTED_SIGNATURE, Boolean.FALSE));
            add(new InternalKeyBindingProperty<Integer>(PROPERTY_UNTIL_NEXT_UPDATE, 0));
            add(new InternalKeyBindingProperty<Integer>(PROPERTY_MAX_AGE, 0));
        }});
    }
    
    @Override
    public String getImplementationAlias() {
        return IMPLEMENTATION_ALIAS;
    }
    
    @Override
    public float getLatestVersion() {
        return Long.valueOf(serialVersionUID).floatValue();
    }

    @Override
    protected void upgrade(float latestVersion, float currentVersion) {
        // Nothing to do
    }
    
    @Override
    public void assertCertificateCompatability(Certificate certificate) throws CertificateImportException {
        if (!isOcspSigningCertificate(certificate)) {
            throw new CertificateImportException();
        }
    }

    public boolean getNonExistingGood() {
        return (Boolean) getProperty(PROPERTY_NON_EXISTING_GOOD).getValue();
    }
    public void setNonExistingGood(boolean nonExistingGood) {
        setProperty(PROPERTY_NON_EXISTING_GOOD, Boolean.valueOf(nonExistingGood));
    }
    public boolean getIncludeCertCertChain() {
        return (Boolean) getProperty(PROPERTY_INCLUDE_CERT_CHAIN).getValue();
    }
    public void setIncludeCertCertChain(boolean includeCertChain) {
        setProperty(PROPERTY_INCLUDE_CERT_CHAIN, Boolean.valueOf(includeCertChain));
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
    public int getUntilNextUpdate() {
        return (Integer) getProperty(PROPERTY_UNTIL_NEXT_UPDATE).getValue();
    }
    public void setUntilNextUpdate(int untilNextUpdate) {
        setProperty(PROPERTY_UNTIL_NEXT_UPDATE, Integer.valueOf(untilNextUpdate));
    }
    public int getMaxAge() {
        return (Integer) getProperty(PROPERTY_MAX_AGE).getValue();
    }
    public void setMaxAge(int maxAge) {
        setProperty(PROPERTY_MAX_AGE, Integer.valueOf(maxAge));
    }

    public static boolean isOcspSigningCertificate(Certificate certificate) {
        if (!(certificate instanceof X509Certificate)) {
            log.debug("Only X509 supported.");
            return false;
        }
        try {
            final X509Certificate x509Certificate = (X509Certificate) certificate;
            log.debug("SubjectDN: " + CertTools.getSubjectDN(x509Certificate) + " IssuerDN: " + CertTools.getIssuerDN(x509Certificate));
            log.debug("Key usages: " + Arrays.toString(x509Certificate.getKeyUsage()));
            log.debug("Key usage (digitalSignature): " + x509Certificate.getKeyUsage()[0]);
            log.debug("Key usage (keyEncipherment): " + x509Certificate.getKeyUsage()[2]);
            for (String extendedKeyUsage : x509Certificate.getExtendedKeyUsage()) {
                log.debug("EKU: " + extendedKeyUsage + " (" +
                        ExtendedKeyUsageConfiguration.getExtendedKeyUsageOidsAndNames().get(extendedKeyUsage) + ")");
            }
            if (!x509Certificate.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.9")) {
                log.debug("Extended Key Usage 1.3.6.1.5.5.7.3.9 (EKU_PKIX_OCSPSIGNING) is required.");
                return false;
            }
            if (!x509Certificate.getKeyUsage()[0]) {
                log.debug("Key Usage digitalSignature is required.");
                return false;
            }
        } catch (CertificateParsingException e) {
            log.debug(e.getMessage());
            return false;
        }

        log.warn("CERTIFICATE VALIDATION HAS NOT BEEN IMPLEMENTED YET!");
        return true;
    }
}
