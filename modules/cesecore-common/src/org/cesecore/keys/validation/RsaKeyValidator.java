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

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.math.Primes;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.profiles.Profile;

/**
 * Default RSA key validator. 
 * 
 * The key validator is used to implement the CA/B-Forum requirements for RSA public 
 * key quality requirements, including FIPS 186-4 and NIST (SP 800-89 and NIST SP 56A: Revision 2)
 * requirements. See: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.4.2.pdf section 6.1.6
 * 
 * @version $Id$
 */
public class RsaKeyValidator extends KeyValidatorBase implements KeyValidator {

    private static final long serialVersionUID = -335429118359811926L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(RsaKeyValidator.class);

    /** MUST be at least 2048 bits key size. */
    public static final int CAB_FORUM_BLR_142_KEY_SIZE_MIN = 2048;
    
    /** SHOULD be odd exponent. */
    public static final boolean CAB_FORUM_BLR_142_PUBLIC_EXPONENT_ONLY_ALLOW_ODD = true;

    /** MUST be >= 3, SHOULD be > 2^16+1 = 65.536+1 */
    public static final String CAB_FORUM_BLR_142_PUBLIC_EXPONENT_MIN = "65537";

    /** SHOULD be <= 2^256-1 = 115792089237316195423570985008687907853269984665640564039457584007913129639936-1 = 2^64*2^4-1 */
    public static final String CAB_FORUM_BLR_142_PUBLIC_EXPONENT_MAX = "115792089237316195423570985008687907853269984665640564039457584007913129639935";

    /** SHOULD be odd modulus. */
    public static final boolean CAB_FORUM_BLR_142_PUBLIC_MODULUS_ONLY_ALLOW_ODD = true;

    /** SHOULD not be the power of a prime. */
    public static final boolean CAB_FORUM_BLR_142_PUBLIC_MODULUS_DONT_ALLOW_POWER_OF_PRIME = true;

    /** SHOULD be with smallest factor >= 752 */
    public static final int CAB_FORUM_BLR_142_PUBLIC_MODULUS_SMALLEST_FACTOR = 752;

    /** The key validator type. */
    private static final String TYPE_IDENTIFIER = "RSA_KEY_VALIDATOR";

    /** View template in /ca/editkeyvalidators. */
    protected static final String TEMPLATE_FILE = "editRsaKeyValidator.xhtml";

    protected static final String BIT_LENGTHS = "bitLengths";

    protected static final String PUBLIC_KEY_EXPONENT_ONLY_ALLOW_ODD = "publicKeyExponentOnlyAllowOdd";

    protected static final String PUBLIC_KEY_EXPONENT_MIN = "publicKeyExponentMin";

    protected static final String PUBLIC_KEY_EXPONENT_MAX = "publicKeyExponentMax";

    protected static final String PUBLIC_KEY_MODULUS_ONLY_ALLOW_ODD = "publicKeyModulusOnlyAllowOdd";

    protected static final String PUBLIC_KEY_MODULUS_DONT_ALLOW_POWER_OF_PRIME = "publicKeyModulusDontAllowPowerOfPrime";

    protected static final String PUBLIC_KEY_MODULUS_MIN_FACTOR = "publicKeyModulusMinFactor";

    protected static final String PUBLIC_KEY_MODULUS_MIN = "publicKeyModulusMin";

    protected static final String PUBLIC_KEY_MODULUS_MAX = "publicKeyModulusMax";

    /**
     * Tests if the factors of the BigInteger modulus are prime.
     * @param modulus the big integer modulus to test
     * @return true if the modulus is power of a prime, false otherwise.
     */
    protected static boolean isPowerOfPrime(BigInteger modulus) {
        // The isPowerOfPrime test is copied from org.bouncycastle.crypto.asymmetric.KeyUtils in the BC-FIPS package.
        // If we move to use the FIPS provider we can use the methods directly instead
        // --- Begin BC code
        // Use the same iterations as if we were testing a candidate p or q value with error probability 2^-100
        int bits = modulus.bitLength();
        int iterations = bits >= 1536 ? 3
            : bits >= 1024 ? 4
            : bits >= 512 ? 7
            : 50;
        // SP 800-89 requires use of an approved DRBG.
//        SecureRandom testRandom = FipsDRBG.SHA256.fromEntropySource(new SecureRandom(), false)
//            .build(Pack.longToBigEndian(System.currentTimeMillis()), false, Strings.toByteArray(Thread.currentThread().toString()));
        SecureRandom testRandom = new SecureRandom(); // we cheat a little and use regular SecureRandom, which is good
        Primes.MROutput mr = Primes.enhancedMRProbablePrimeTest(modulus, testRandom, iterations);
        if (!mr.isProvablyComposite())
        {
            // FSM_TRANS:5.16, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test failed"
            log.debug("RSA modulus is not composite");
            return true;
        }
        if (!mr.isNotPrimePower())
        {
            // FSM_TRANS:5.16, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test failed"
            log.debug("RSA modulus is a power of a prime");
            return true;
        }
        // --- end BC code
        return false;
    }
//    public static boolean isPowerOfPrime(BigInteger modulus) {
//        BigInteger n = modulus;
//        final Set<BigInteger> result = new TreeSet<BigInteger>();
//        for (BigInteger i = BigInteger.valueOf(2); i.compareTo(n.divide(i).add(BigInteger.ONE)) == -1; i = i.add(BigInteger.ONE)) {
//            while (n.mod(i).compareTo(BigInteger.ZERO) == 0) {
//                if (result.contains(i)) { // is power of a prime.
//                    return true;
//                }
//                result.add(i);
//                n = n.divide(i);
//            }
//        }
//        if (n.compareTo(BigInteger.ONE) == 1) {
//            if (result.contains(n)) { // is power of a prime.
//                return true;
//            }
//            result.add(n);
//        }
//        return false;
//    }

//  /**
  //     * Checks if the given value is a prime.
  //     * @param value the positive integer value.
  //     * @return true if the value is a prime.
  //     */
  //    public static final boolean isPrime(BigInteger value) {
  //        if (!value.isProbablePrime(5)) {
  //            return false;
  //        }
  //        final BigInteger two = BigInteger.valueOf(2);
  //        if (!two.equals(value) && BigInteger.ZERO.equals(value.mod(two))) {
  //            return false;
  //        }
  //        for (BigInteger i = BigInteger.valueOf(3); i.multiply(i).compareTo(value) < 1; i = i.add(two)) {
  //            if (value.mod(i).equals(BigInteger.ZERO)) {
  //                return false;
  //            }
  //        }
  //        return true;
  //    }
    
    /**
     * Gets the smallest factor of the positive natural number greater than 2.
     * @param n the number
     * @return the smallest factor or 2 for n=0.
     */
    protected static final boolean hasSmallerFactorThan(BigInteger n, int intFactor) {
        //        BigInteger factor = BigInteger.valueOf(intFactor);
        final BigInteger two = new BigInteger("2");
        if (intFactor < 3) {
            return false;
        }
        if (n.mod(two).equals(BigInteger.ZERO) && intFactor > 2) {
            return true;
        }
        for (int i = intFactor; i > 2; i = i - 2) {
            if (n.mod(BigInteger.valueOf(i)).equals(BigInteger.ZERO)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Public constructor needed for deserialization.
     */
    public RsaKeyValidator() {
        super();
        init();
    }

    /**
     * Creates a new instance.
     */
    public RsaKeyValidator(final String name) {
        super(name);
        init();
    }

    /**
     * Creates a new instance with the same attributes as the given one.
     * @param keyValidator the base key validator to load.
     */
    public RsaKeyValidator(final KeyValidatorBase keyValidator) {
        super(keyValidator);
    }

    @Override
    public void init() {
        super.init();
        if (null == data.get(BIT_LENGTHS)) {
            setBitLengths(new ArrayList<String>());
        }
        if (null == data.get(PUBLIC_KEY_EXPONENT_ONLY_ALLOW_ODD)) {
            setPublicKeyExponentOnlyAllowOdd(false);
        }
        if (null == data.get(PUBLIC_KEY_MODULUS_ONLY_ALLOW_ODD)) {
            setPublicKeyModulusOnlyAllowOdd(false);
        }
        if (null == data.get(PUBLIC_KEY_MODULUS_DONT_ALLOW_POWER_OF_PRIME)) {
            setPublicKeyModulusDontAllowPowerOfPrime(false);
        }
    }

    @Override
    public void setKeyValidatorSettingsTemplate() {
        final int option = getSettingsTemplate();
        if (log.isDebugEnabled()) {
            log.debug("Set configuration template for RSA key validator settings option: "
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
    public void setEmptyCustomSettings() {
        setBitLengths(new ArrayList<String>());
        setPublicKeyExponentOnlyAllowOdd(false);
        setPublicKeyExponentMin(null);
        setPublicKeyExponentMax(null);
        setPublicKeyModulusOnlyAllowOdd(false);
        setPublicKeyModulusDontAllowPowerOfPrime(false);
        setPublicKeyModulusMinFactor(null);
        setPublicKeyModulusMin(null);
        setPublicKeyModulusMax(null);
    }

    /**
     * Sets the CA/B Forum requirements chapter 6.1.6 for RSA public keys.
     * @see {@link https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.4.2.pdf}
     * @param keyValidator
     */
    public void setCABForumBaseLineRequirements142Settings() {
        // Only apply most important conditions (sequence is Root-CA, Sub-CA, User-Certificate)!
        // But this is not required at the time, because certificate validity conditions are before 
        // 2014 (now 2017). The minimal modulus size (2048 bits) is the same for all certificate types! 
        setBitLengths(getAvailableBitLengths(2048));
        final List<Integer> ids = getCertificateProfileIds();
        if (ids.contains(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA)) {
            // NOOP
        } else if (ids.contains(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA)) {
            // NOOP
        } else {
            // NOOP
        }
        setPublicKeyExponentOnlyAllowOdd(CAB_FORUM_BLR_142_PUBLIC_EXPONENT_ONLY_ALLOW_ODD);
        setPublicKeyExponentMin(new BigInteger(CAB_FORUM_BLR_142_PUBLIC_EXPONENT_MIN));
        setPublicKeyExponentMax(new BigInteger(CAB_FORUM_BLR_142_PUBLIC_EXPONENT_MAX));
        setPublicKeyModulusOnlyAllowOdd(CAB_FORUM_BLR_142_PUBLIC_MODULUS_ONLY_ALLOW_ODD);
        setPublicKeyModulusDontAllowPowerOfPrime(CAB_FORUM_BLR_142_PUBLIC_MODULUS_DONT_ALLOW_POWER_OF_PRIME);
        setPublicKeyModulusMinFactor(CAB_FORUM_BLR_142_PUBLIC_MODULUS_SMALLEST_FACTOR);
        setPublicKeyModulusMin(null);
        setPublicKeyModulusMax(null);
    }

    @SuppressWarnings("unchecked")
    public List<String> getBitLengths() {
        return (List<String>) data.get(BIT_LENGTHS);
    }

    public void setBitLengths(List<String> values) {
        Collections.sort(values);
        data.put(BIT_LENGTHS, values);
    }

    public boolean isPublicKeyExponentOnlyAllowOdd() {
        return ((Boolean) data.get(PUBLIC_KEY_EXPONENT_ONLY_ALLOW_ODD)).booleanValue();
    }

    public void setPublicKeyExponentOnlyAllowOdd(boolean allowed) {
        data.put(PUBLIC_KEY_EXPONENT_ONLY_ALLOW_ODD, Boolean.valueOf(allowed));
    }

    public BigInteger getPublicKeyExponentMin() {
        if (StringUtils.isNotBlank((String) data.get(PUBLIC_KEY_EXPONENT_MIN))) {
            return new BigInteger(((String) data.get(PUBLIC_KEY_EXPONENT_MIN)));
        } else {
            return null;
        }
    }

    public String getPublicKeyExponentMinAsString() {
        return (String) data.get(PUBLIC_KEY_EXPONENT_MIN);
    }

    public void setPublicKeyExponentMin(BigInteger value) {
        if (null != value) {
            data.put(PUBLIC_KEY_EXPONENT_MIN, value.toString());
        } else {
            data.put(PUBLIC_KEY_EXPONENT_MIN, null);
        }
    }

    public void setPublicKeyExponentMinAsString(String value) {
        data.put(PUBLIC_KEY_EXPONENT_MIN, value);
    }

    public BigInteger getPublicKeyExponentMax() {
        if (StringUtils.isNotBlank((String) data.get(PUBLIC_KEY_EXPONENT_MAX))) {
            return new BigInteger(((String) data.get(PUBLIC_KEY_EXPONENT_MAX)));
        } else {
            return null;
        }
    }

    public String getPublicKeyExponentMaxAsString() {
        return (String) data.get(PUBLIC_KEY_EXPONENT_MAX);
    }

    public void setPublicKeyExponentMax(BigInteger value) {
        if (null != value) {
            data.put(PUBLIC_KEY_EXPONENT_MAX, value.toString());
        } else {
            data.put(PUBLIC_KEY_EXPONENT_MAX, null);
        }
    }

    public void setPublicKeyExponentMaxAsString(String value) {
        data.put(PUBLIC_KEY_EXPONENT_MAX, value);
    }

    public boolean isPublicKeyModulusOnlyAllowOdd() {
        return ((Boolean) data.get(PUBLIC_KEY_MODULUS_ONLY_ALLOW_ODD)).booleanValue();
    }

    public void setPublicKeyModulusOnlyAllowOdd(boolean allowed) {
        data.put(PUBLIC_KEY_MODULUS_ONLY_ALLOW_ODD, Boolean.valueOf(allowed));
    }

    public boolean isPublicKeyModulusDontAllowPowerOfPrime() {
        return ((Boolean) data.get(PUBLIC_KEY_MODULUS_DONT_ALLOW_POWER_OF_PRIME)).booleanValue();
    }

    public void setPublicKeyModulusDontAllowPowerOfPrime(boolean allowed) {
        data.put(PUBLIC_KEY_MODULUS_DONT_ALLOW_POWER_OF_PRIME, Boolean.valueOf(allowed));
    }

    public Integer getPublicKeyModulusMinFactor() {
        return (Integer) data.get(PUBLIC_KEY_MODULUS_MIN_FACTOR);
    }

    public void setPublicKeyModulusMinFactor(Integer type) {
        data.put(PUBLIC_KEY_MODULUS_MIN_FACTOR, type);
    }

    public BigInteger getPublicKeyModulusMin() {
        if (StringUtils.isNotBlank((String) data.get(PUBLIC_KEY_MODULUS_MIN))) {
            return new BigInteger(((String) data.get(PUBLIC_KEY_MODULUS_MIN)));
        } else {
            return null;
        }
    }

    public String getPublicKeyModulusMinAsString() {
        return (String) data.get(PUBLIC_KEY_MODULUS_MIN);
    }

    public void setPublicKeyModulusMin(BigInteger value) {
        if (null != value) {
            data.put(PUBLIC_KEY_MODULUS_MIN, value.toString());
        } else {
            data.put(PUBLIC_KEY_MODULUS_MIN, null);
        }
    }

    public void setPublicKeyModulusMinAsString(String value) {
        data.put(PUBLIC_KEY_MODULUS_MIN, value);
    }

    public BigInteger getPublicKeyModulusMax() {
        if (StringUtils.isNotBlank((String) data.get(PUBLIC_KEY_MODULUS_MAX))) {
            return new BigInteger((String) data.get(PUBLIC_KEY_MODULUS_MAX));
        } else {
            return null;
        }
    }

    public String getPublicKeyModulusMaxAsString() {
        return (String) data.get(PUBLIC_KEY_MODULUS_MAX);
    }

    public void setPublicKeyModulusMax(BigInteger value) {
        if (null != value) {
            data.put(PUBLIC_KEY_MODULUS_MAX, value.toString());
        } else {
            data.put(PUBLIC_KEY_MODULUS_MAX, null);
        }
    }

    public void setPublicKeyModulusMaxAsString(String value) {
        data.put(PUBLIC_KEY_MODULUS_MAX, value);
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
            log.info(intres.getLocalizedMessage("rsakeyvalidator.upgrade", new Float(getVersion())));
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
        if (!AlgorithmConstants.KEYALGORITHM_RSA.equals(publicKey.getAlgorithm()) || !(publicKey instanceof RSAPublicKey)) {
            final String message = "Invalid: Public key algorithm is not RSA or could not be parsed: " + publicKey.getAlgorithm() + ", format "
                    + publicKey.getFormat();
            messages.add(message);
            // Make sure this ends up in the server log
            log.info(message+", "+publicKey.getClass().getName());
            throw new ValidatorNotApplicableException(message);
        }
        final RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        final BigInteger publicKeyExponent = rsaPublicKey.getPublicExponent();
        final BigInteger publicKeyModulus = rsaPublicKey.getModulus();
        if (log.isDebugEnabled()) {
            log.debug("Validate RSA public key with exponent " + publicKeyExponent + " and modulus " + publicKeyModulus);
        }
        final int settingsOption = getSettingsTemplate();
        final int keyLength = KeyTools.getKeyLength(publicKey);
        if (KeyValidatorSettingsTemplate.USE_CERTIFICATE_PROFILE_SETTINGS.getOption() == settingsOption) {
            final List<Integer> bitLengths = certificateProfile.getAvailableBitLengthsAsList();
            if (!bitLengths.contains(Integer.valueOf(keyLength))) {
                // Invalid Key in request: Illegal key length, not authorized by certificate profile: 2048.. Please supply a correct request.
                messages.add("Invalid: RSA key size/strength: Use one of the following " + bitLengths + ".");
            }
        } else {
            final List<String> bitLengths = getBitLengths();
            if (!bitLengths.contains(Integer.toString(keyLength))) {
                messages.add("Invalid: RSA key size/strength: Use one of the following " + bitLengths + ".");
            }
        }
        if (isPublicKeyExponentOnlyAllowOdd()) {
            if (publicKeyExponent.mod(BigInteger.valueOf(2L)).compareTo(BigInteger.ZERO) == 0) {
                messages.add("Invalid: RSA public key exponent is odd.");
            } else {
                log.trace("isPublicKeyExponentOnlyAllowOdd passed");
            }
        }
        if (null != getPublicKeyExponentMin()) {
            if (publicKeyExponent.compareTo(getPublicKeyExponentMin()) == -1) {
                messages.add("Invalid: RSA public key exponent is smaller than " + getPublicKeyExponentMin());
            } else {
                log.trace("getPublicKeyExponentMin passed");
            }
        }
        if (null != getPublicKeyExponentMax()) {
            if (publicKeyExponent.compareTo(getPublicKeyExponentMax()) == 1) {
                messages.add("Invalid: RSA public key exponent is greater than " + getPublicKeyExponentMax());
            }
        }
        if (isPublicKeyModulusOnlyAllowOdd()) {
            if (publicKeyModulus.mod(BigInteger.valueOf(2L)).compareTo(BigInteger.ZERO) == 0) {
                messages.add("Invalid: RSA public key modulus is odd.");
            } else {
                log.trace("isPublicKeyModulusOnlyAllowOdd passed");
            }
        }
        if (isPublicKeyModulusDontAllowPowerOfPrime()) {
            if (isPowerOfPrime(publicKeyModulus)) {
                messages.add("Invalid: RSA public key modulus is not allowed to be the power of a prime.");
            } else {
                log.trace("isPublicKeyModulusDontAllowPowerOfPrime passed");
            }
        }
        if (null != getPublicKeyModulusMinFactor()) {
            if (hasSmallerFactorThan(publicKeyModulus, getPublicKeyModulusMinFactor() + 1)) {
                messages.add("Invalid: RSA public key modulus smallest factor is less than " + getPublicKeyModulusMinFactor());
            } else {
                log.trace("getPublicKeyModulusMinFactor passed");
            }
        }
        if (null != getPublicKeyModulusMin()) {
            if (publicKeyModulus.compareTo(getPublicKeyModulusMin()) == -1) {
                messages.add("Invalid: RSA public key modulus is smaller than " + getPublicKeyModulusMin());
            } else {
                log.trace("getPublicKeyModulusMin passed");
            }
        }
        if (null != getPublicKeyModulusMax()) {
            if (publicKeyModulus.compareTo(getPublicKeyModulusMax()) == 1) {
                messages.add("Invalid: RSA public key modulus is greater than " + getPublicKeyModulusMax());
            } else {
                log.trace("getPublicKeyModulusMax passed");
            }
        }

        if (log.isDebugEnabled()) {
            for (String message : messages) {
                log.debug(message);
            }
        }
        return messages;
    }

    /**
     * Gets the available bit lengths to choose.
     * @return the list of available bit lengths.
     */
    public List<String> getAvailableBitLengths() {
        final List<String> result = new ArrayList<String>();
        for (int length : CertificateProfile.DEFAULTBITLENGTHS) {
            result.add(Integer.toString(length));
        }
        return result;
    }

    /**
     * Gets the available bit lengths to choose.
     * @return the list of available bit lengths.
     */
    public static List<String> getAvailableBitLengths(final int minLength) {
        final List<String> result = new ArrayList<String>();
        for (int length : CertificateProfile.DEFAULTBITLENGTHS) {
            if (length >= minLength) {
                result.add(Integer.toString(length));
            }
        }
        return result;
    }
    
    @Override
    public String getLabel() {
        return intres.getLocalizedMessage("validator.implementation.key.rsa");
    }

    @Override
    public String getValidatorTypeIdentifier() {
        return TYPE_IDENTIFIER;
    }

    @Override
    protected Class<? extends Profile> getImplementationClass() {
        return RsaKeyValidator.class;
    }
}
