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
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.math.ec.ECPoint;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.profiles.Profile;
import org.cesecore.util.ui.DynamicUiActionCallback;
import org.cesecore.util.ui.DynamicUiCallbackException;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Default ECC key validator using the Bouncy Castle BCECPublicKey implementation 
 * (see org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey). 
 * 
 * The key validator is used to implement the CA/B-Forum requirements for RSA public 
 * key quality requirements, including FIPS 186-4 and NIST (SP 800-89 and NIST SP 56A: Revision 2)
 * requirements. See: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.4.2.pdf section 6.1.6
 * 
 * @version $Id$
 */
public class EccKeyValidator extends KeyValidatorBase {

    private static final long serialVersionUID = -335429158339811928L;

    private static final Logger log = Logger.getLogger(EccKeyValidator.class);

    /** The key validator type. */
    private static final String TYPE_IDENTIFIER = "ECC_KEY_VALIDATOR";

    protected static final String CURVES = "ecCurves";

    protected static final String USE_FULL_PUBLIC_KEY_VALIDATION_ROUTINE = "useFullPublicKeyValidationRoutine";
        
    /**
     * Public constructor needed for deserialization.
     */
    public EccKeyValidator() {
        super();
    }
    
    /**
     * Creates a new instance.
     */
    public EccKeyValidator(final String name) {
        super(name);
    }

    /**
     * Initializes uninitialized data fields.
     */
    @Override
    public void init() {
        super.init();
        if (null == data.get(CURVES)) {
            setCurves(new ArrayList<String>());
        }
        if (data.get(USE_FULL_PUBLIC_KEY_VALIDATION_ROUTINE) == null) {
            setUseFullPublicKeyValidationRoutine(true);
        }
    }

    @Override
    @SuppressWarnings({"serial", "unchecked"})
    public void initDynamicUiModel() {
        uiModel = new DynamicUiModel(data);
        uiModel.add(new DynamicUiProperty<String>("settings"));
        final DynamicUiProperty<Integer> settingsTemplate = new DynamicUiProperty<Integer>(Integer.class, SETTINGS_TEMPLATE, getSettingsTemplate(), KeyValidatorSettingsTemplate.types());
        settingsTemplate.setRenderingHint(DynamicUiProperty.RENDER_SELECT_ONE);
        settingsTemplate.setLabels(KeyValidatorSettingsTemplate.map());
        settingsTemplate.setRequired(true);
        settingsTemplate.setActionCallback(new DynamicUiActionCallback() {
            @Override
            public void action(final Object parameter) throws DynamicUiCallbackException {
                final Map<Object, Object> oldValues = (Map<Object, Object>) data.clone();
                setKeyValidatorSettingsTemplate(KeyValidatorSettingsTemplate.optionOf(Integer.parseInt((String) parameter)));
                uiModel.firePropertyChange(oldValues, data);
            }
            @Override
            public List<String> getRender() {
                return null;
            }
        });
        uiModel.add(settingsTemplate);
        final DynamicUiProperty<String> curves = new DynamicUiProperty<String>(String.class, CURVES, getCurvesAsString(), 
                new ArrayList<String>(AlgorithmTools.getFlatNamedEcCurvesMap(false).keySet())) {
                    @Override
                    public boolean isDisabled() { return isCurvesDisabled(); }
        };
        curves.setLabels(AlgorithmTools.getFlatNamedEcCurvesMap(false));
        curves.setHasMultipleValues(true);
        curves.setRequired(true);
        uiModel.add(curves);
        uiModel.add(new DynamicUiProperty<Boolean>(Boolean.class, USE_FULL_PUBLIC_KEY_VALIDATION_ROUTINE, isUseFullPublicKeyValidationRoutine()) {
            @Override
            public boolean isDisabled() { return isPropertyDisabled(); }
        });
    }
    
    /**
     * Returns true if the dynamic property fields for this validator are supposed to be disabled.
     * @return true if disabled.
     */
    private final boolean isPropertyDisabled() {
        return KeyValidatorSettingsTemplate.USE_CAB_FORUM_SETTINGS.getOption() == getSettingsTemplate();
    }
    
    /**
     * Returns true if the dynamic property fields for this validator are supposed to be disabled.
     * @return true if disabled.
     */
    private final boolean isCurvesDisabled() {
        return KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption() != getSettingsTemplate();
    }
        
    @Override
    public void setKeyValidatorSettingsTemplate(final KeyValidatorSettingsTemplate template) {
        setSettingsTemplate(template.getOption());
        if (log.isDebugEnabled()) {
            log.debug("Set configuration template for ECC key validator settings option: "
                    + intres.getLocalizedMessage(template.getLabel()));
        }
        if (KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.equals(template)) {
            // NOOP: In the validation method, the key specification is matched against the certificate profile.
        } else if (KeyValidatorSettingsTemplate.USE_CAB_FORUM_SETTINGS.equals(template)) {
            setCABForumBaseLineRequirements142Settings();
            setUseFullPublicKeyValidationRoutine(true);
        } else if (KeyValidatorSettingsTemplate.USE_CERTIFICATE_PROFILE_SETTINGS.equals(template)) {
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
        setCurves(AlgorithmTools.getNistCurves());
        setUseFullPublicKeyValidationRoutine(true);
    }

    @SuppressWarnings("unchecked")
    public List<String> getCurves() {
        return (List<String>) data.get(CURVES);
    }
    
    public String getCurvesAsString() {
        return getCurves() != null ? StringUtils.join(getCurves(), LIST_SEPARATOR) : StringUtils.EMPTY;
    }

    public void setCurves(List<String> values) {
        data.put(CURVES, values);
    }

    /**
     * Use full public key validation routine.
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
    public List<String> validate(final PublicKey publicKey, final CertificateProfile certificateProfile) throws ValidatorNotApplicableException, ValidationException {
        List<String> messages = new ArrayList<String>();
        if (log.isDebugEnabled()) {
            log.debug("Validating public key with algorithm " + publicKey.getAlgorithm() + ", format " + publicKey.getFormat() + ", implementation "
                    + publicKey.getClass().getName());
        }
        if (!(AlgorithmConstants.KEYALGORITHM_ECDSA.equals(publicKey.getAlgorithm()) || AlgorithmConstants.KEYALGORITHM_EC.equals(publicKey.getAlgorithm())) || !(publicKey instanceof ECPublicKey)) {
            final String message = "Invalid: Public key is not ECC algorithm or could not be parsed: " + publicKey.getAlgorithm() + ", format "
                    + publicKey.getFormat();
            messages.add(message);
            throw new ValidatorNotApplicableException(message);
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
            boolean found = false;
            for (final String ecNamedCurveAlias : AlgorithmTools.getEcKeySpecAliases(keySpecification)) {
                if (availableEcCurves.contains(ecNamedCurveAlias)) {
                    found = true;
                }
            }
            if (!found) {
                messages.add("Invalid: ECDSA curve "+AlgorithmTools.getEcKeySpecAliases(keySpecification)+": Use one of the following " + availableEcCurves + ".");
            }
        }
        
        if (isUseFullPublicKeyValidationRoutine()) {
            if (log.isDebugEnabled()) {
                log.debug("Performing full EC public key validation.");
            }
            // The FullPublicKeyValidationRoutine test is copied from org.bouncycastle.crypto.asymmetric.KeyUtils in the BC-FIPS package.
            // If we move to use the FIPS provider we can use the methods directly instead

            // Source-wise org.bouncycastle.crypto.asymmetric.KeyUtils in the BCFIPS
            // library is the place with - the code refers to SP 800-89 which is the
            // same validation (the full one) referred to in SP 800-56A, the original
            // source document for both is actually X9.62.
            // org.bouncycastle.math.ec.ECPoint has the "business end" of the code on
            // starting on line 286, implIsValid(). For key validation purposes
            // checkOrder is true so subgroup membership is always checked

            // First convert the Java.security publicKey into a BC ECPoint
            ECPoint q = EC5Util.convertPoint(bcEcPublicKey.getParams(), bcEcPublicKey.getW(), false);

            // --- Begin BC code
            // FSM_STATE:5.9, "FIPS 186-3/SP 800-89 ASSURANCES", "The module is performing FIPS 186-3/SP 800-89 Assurances self-test"
            // FSM_TRANS:5.14, "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "Invoke FIPS 186-3/SP 800-89 Assurances test"
            if (q == null)
            {
                // FSM_TRANS:5.16, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test failed"
                messages.add("Invalid: EC key point has null value.");
            } else {
                log.trace("EC point has value test passed");
            }

            if (q.isInfinity())
            {
                // FSM_TRANS:5.16, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test failed"
                messages.add("Invalid: EC key point at infinity.");
            } else {
                log.trace("EC point not on infinity test passed");
            }

            q = q.normalize();

            if (!q.isValid())
            {
                // FSM_TRANS:5.16, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test failed"
                messages.add("Invalid: EC key point not on curve.");
            } else {
                log.trace("EC point not on curve test passed");
            }
        }
        // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test successful"
        // --- End BC code

        if (log.isDebugEnabled()) {
            for (String message : messages) {
                log.debug(message);
            }
        }
        return messages;
    }

    /**
     * Sets the CA/B Forum requirements chapter 6.1.6 for ECC public keys.
     * @see {@link https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.4.2.pdf}
     */
    public final void setCABForumBaseLineRequirements142() {
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
