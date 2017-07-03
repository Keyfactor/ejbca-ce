/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.profiles.Profile;

/**
 * Default ECC key validator using the Bouncy Castle BCECPublicKey implementation 
 * (see org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey). 
 * 
 * The key validator is used to implement the CA/B-Forum requirements for RSA public 
 * key quality requirements, including FIPS 186-4 and NIST (SP 800-89 and NIST SP 56A: Revision 2)
 * requirements. See: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.4.2.pdf
 * 
 * @version $Id$
 */
public class EccKeyValidator extends KeyValidatorBase {

    private static final long serialVersionUID = -335429158339811928L;

    private static final Logger log = Logger.getLogger(EccKeyValidator.class);

    public static final float LATEST_VERSION = 1;

    /** The key validator type. */
    private static final String TYPE_IDENTIFIER = "ECC_KEY_VALIDATOR";

    /** View template in /ca/editkeyvalidators. */
    protected static final String TEMPLATE_FILE = "editEccKeyValidator.xhtml";

    protected static final String CURVES = "ecCurves";

    protected static final String USE_PARTIAL_PUBLIC_KEY_VALIDATION_ROUTINE = "usePartialPublicKeyValidationRoutine";

    protected static final String USE_FULL_PUBLIC_KEY_VALIDATION_ROUTINE = "useFullPublicKeyValidationRoutine";

    
    /**
     * Public constructor needed for deserialization.
     */
    public EccKeyValidator() {
        super();
        init();
    }
    
    /**
     * Creates a new instance.
     */
    public EccKeyValidator(final String name) {
        super(name);
        init();
    }

    /**
     * Creates a new instance with the same attributes as the given one.
     * @param keyValidator the base key validator to load.
     */
    public EccKeyValidator(final KeyValidatorBase keyValidator) {
        super(keyValidator);
    }

    /**
     * Initializes uninitialized data fields.
     */
    public void init() {
        super.init();
        if (null == data.get(CURVES)) {
            setCurves(new ArrayList<String>());
        }
        if (data.get(USE_PARTIAL_PUBLIC_KEY_VALIDATION_ROUTINE) == null) {
            setUsePartialPublicKeyValidationRoutine(false);
        }
        if (data.get(USE_FULL_PUBLIC_KEY_VALIDATION_ROUTINE) == null) {
            setUseFullPublicKeyValidationRoutine(false);
        }
    }

    @Override
    public void setKeyValidatorSettingsTemplate() {
        final int option = getSettingsTemplate();
        if (log.isDebugEnabled()) {
            log.debug("Set configuration template for ECC key validator settings option: "
                    + intres.getLocalizedMessage(KeyValidatorSettingsTemplate.optionOf(option).getLabel()));
        }
        if (KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption() == option) {
            //            setEmptyCustomSettings();
        } else if (KeyValidatorSettingsTemplate.USE_CAB_FORUM_SETTINGS.getOption() == option) {
            setCABForumBaseLineRequirements142Settings();
        } else if (KeyValidatorSettingsTemplate.USE_CERTIFICATE_PROFILE_SETTINGS.getOption() == option) {
            // NOOP: In the validation method, the key specification is matched against the certificate profile.
        } else {
            // NOOP
        }
    }

    /**
     * Sets the CA/B Forum requirements chapter 6.1.6 for RSA public keys.
     * @see {@link https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.4.2.pdf}
     * @param keyValidator
     */
    public void setCABForumBaseLineRequirements142Settings() {
        // Only apply most important conditions (sequence is Root-CA, Sub-CA, User-Certificate)!
        // But this is not required at the time, because certificate validity conditions are before 
        // 2014 (now 2017). Allowed curves by NIST are NIST P 256, P 384, P 512
        // See http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf chapter 1.2

        final List<String> allowedCurves = new ArrayList<String>();
        //        allowedCurves.add
        setCurves(allowedCurves);
        final List<Integer> ids = getCertificateProfileIds();
        if (ids.contains(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA)) {
            // NOOP
        } else if (ids.contains(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA)) {
            // NOOP
        } else {
            // NOOP
        }
        setUsePartialPublicKeyValidationRoutine(true);
        setUseFullPublicKeyValidationRoutine(true);
    }

    @SuppressWarnings("unchecked")
    public List<String> getCurves() {
        return (List<String>) data.get(CURVES);
    }

    public void setCurves(List<String> values) {
        data.put(CURVES, values);
    }

    /**
     * Use partial public key validation routine.
     * @return true if has to be used.
     */
    public boolean isUsePartialPublicKeyValidationRoutine() {
        return ((Boolean) data.get(USE_PARTIAL_PUBLIC_KEY_VALIDATION_ROUTINE)).booleanValue();
    }

    /**
     * Use partial public key validation routine.
     * @see <a href="https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.4.2.pdf">CA/B-Forum Baseline Requirements 1.4.2 Chapter 5.6.2.3.2</a>
     * @param use
     */
    public void setUsePartialPublicKeyValidationRoutine(boolean use) {
        data.put(USE_PARTIAL_PUBLIC_KEY_VALIDATION_ROUTINE, Boolean.valueOf(use));
    }

    /**
     * Use partial public key validation routine.
     * @return true if has to be used.
     */
    public boolean isUseFullPublicKeyValidationRoutine() {
        return ((Boolean) data.get(USE_FULL_PUBLIC_KEY_VALIDATION_ROUTINE)).booleanValue();
    }

    /**
     * Use full public key validation routine.
     * @see <a href="https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.4.2.pdf">CA/B-Forum Baseline Requirements 1.4.2 Chapter 5.6.2.3.3s</a>
     * @param use
     */
    public void setUseFullPublicKeyValidationRoutine(boolean allowed) {
        data.put(USE_FULL_PUBLIC_KEY_VALIDATION_ROUTINE, Boolean.valueOf(allowed));
    }

    @Override
    public String getTemplateFile() {
        return TEMPLATE_FILE;
    }

    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public void upgrade() {
        super.upgrade();
        if (log.isTraceEnabled()) {
            log.trace(">upgrade: " + getLatestVersion() + ", " + getVersion());
        }
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade.
            log.info(intres.getLocalizedMessage("ecckeyvalidator.upgrade", new Float(getVersion())));
            init();
        }
    }

    @Override
    public void before() {
        if (log.isDebugEnabled()) {
            log.debug("EccKeyValidator before.");
            // Initialize used objects here.
        }
    }

    @Override
    public boolean validate(final PublicKey publicKey) throws KeyValidationException {
        super.validate(publicKey);
        if (log.isDebugEnabled()) {
            log.debug("Validating public key with algorithm " + publicKey.getAlgorithm() + ", format " + publicKey.getFormat() + ", implementation "
                    + publicKey.getClass().getName());
        }
        if (!AlgorithmConstants.KEYALGORITHM_RSA.equals(publicKey.getAlgorithm()) || !(publicKey instanceof ECPublicKey)) {
            final String message = "Invalid: Public key has no ECC algorithm or could not be parsed: " + publicKey.getAlgorithm() + ", format "
                    + publicKey.getFormat();
            messages.add(message);
            throw new KeyValidationIllegalKeyAlgorithmException(message);
        }
        final ECPublicKey bcEcPublicKey = (ECPublicKey) publicKey;
        if (log.isDebugEnabled()) {
            log.debug("ECC Key algorithm " + bcEcPublicKey.getAlgorithm());
            log.debug("ECC format " + bcEcPublicKey.getFormat());
            log.debug("ECC affine X " + bcEcPublicKey.getW().getAffineX());
            log.debug("ECC affine Y " + bcEcPublicKey.getW().getAffineY());
            log.debug("ECC co factor " + bcEcPublicKey.getParams().getCofactor());
            log.debug("ECC order " + bcEcPublicKey.getParams().getOrder());
            log.debug("ECC generator " + bcEcPublicKey.getParams().getGenerator());
            log.debug("ECC curve seed " + bcEcPublicKey.getParams().getCurve().getSeed());
            log.debug("ECC curve A " + bcEcPublicKey.getParams().getCurve().getA());
            log.debug("ECC curve B " + bcEcPublicKey.getParams().getCurve().getB());
            log.debug("ECC curve field size " + bcEcPublicKey.getParams().getCurve().getField().getFieldSize());
        }

        final List<String> availableEcCurves;
        final int settingsOption = getSettingsTemplate();
        if (KeyValidatorSettingsTemplate.USE_CERTIFICATE_PROFILE_SETTINGS.getOption() == settingsOption) {
            availableEcCurves = certificateProfile.getAvailableEcCurvesAsList();
        } else {
            availableEcCurves = getCurves();
        }
        final String keySpecification = AlgorithmTools.getKeySpecification(publicKey);
        if (log.isDebugEnabled()) {
            log.debug("Matching key specification " + keySpecification + " against allowed ECC curves: " + availableEcCurves);
        }
        if (!availableEcCurves.contains(CertificateProfile.ANY_EC_CURVE)) {
            for (final String ecNamedCurveAlias : AlgorithmTools.getEcKeySpecAliases(keySpecification)) {
                if (!availableEcCurves.contains(ecNamedCurveAlias)) {
                    messages.add("Invalid: " + intres.getLocalizedMessage("createcert.illegaleccurve", keySpecification));
                    break;
                }
            }
        }
        if (isUseFullPublicKeyValidationRoutine()) {
            performFullPublicKeyValidationRoutine(bcEcPublicKey);
        } else if (isUsePartialPublicKeyValidationRoutine()) {
            performPartialPublicKeyValidationRoutine(bcEcPublicKey);
        }
        if (log.isDebugEnabled()) {
            for (String message : getMessages()) {
                log.debug(message);
            }
        }
        return getMessages().size() == 0;
    }

    @Override
    public void after() {
        if (log.isDebugEnabled()) {
            log.debug("EccKeyValidator after.");
            // Finalize used objects here.
        }
    }

    private void performPartialPublicKeyValidationRoutine(final ECPublicKey publicKey) {
        if (log.isTraceEnabled()) {
            log.trace(">performPartialPublicKeyValidationRoutine");
        }
        // ECA-4219 Impl. ECC partial public key validation routine (CAB-Forum requirements ch. 6.1.6)
        if (log.isTraceEnabled()) {
            log.trace("<performPartialPublicKeyValidationRoutine");
        }
    }

    private void performFullPublicKeyValidationRoutine(final ECPublicKey publicKey) {
        if (log.isTraceEnabled()) {
            log.trace(">performFullPublicKeyValidationRoutine");
        }
        // ECA-4219 Impl. ECC full public key validation routine (CAB-Forum requirements ch. 6.1.6)
        if (log.isTraceEnabled()) {
            log.trace("<performFullPublicKeyValidationRoutine");
        }
    }

    /**
     * Sets the CA/B Forum requirements chapter 6.1.6 for ECC public keys.
     * @see {@link https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.4.2.pdf}
     * @param keyValidator
     */
    public final void setCABForumBaseLineRequirements142() {
        // SHOULD use the partial public key validation routine
        setUsePartialPublicKeyValidationRoutine(true);
        // SHOULD use the full public key validation routine
        setUseFullPublicKeyValidationRoutine(true);
    }
    
    @Override
    public String getLabel() {
        return intres.getLocalizedMessage("validator.implementation.key.ecc");
    }

    @Override
    public String getValidatorTypeIdentifier() {
        return TYPE_IDENTIFIER;
    }

    @Override
    protected Class<? extends Profile> getImplementationClass() {
        return EccKeyValidator.class;
    }
}
