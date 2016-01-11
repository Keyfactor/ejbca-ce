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

package org.ejbca.ui.cli.ca;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * CLI command for creating a CA and its first CRL. Publishes the CRL and CA certificate if it should.
 * 
 * @version $Id$
 */
enum CaType {
    X509("x509"), CVC("cvc");

    private static Map<String, CaType> lookupMap;
    private final String typeName;

    static {
        lookupMap = new HashMap<String, CaType>();
        for (CaType type : CaType.values()) {
            lookupMap.put(type.getTypeName(), type);
        }
    }

    private CaType(String name) {
        this.typeName = name;
    }

    public String getTypeName() {
        return this.typeName;
    }

    public static CaType lookupCaType(String typeName) {
        return lookupMap.get(typeName);
    }

    public static String getTypeNames() {
        StringBuilder stringBuilder = new StringBuilder("[");
        for (CaType type : CaType.values()) {
            stringBuilder.append(type.getTypeName());
            stringBuilder.append(",");
        }
        stringBuilder.setCharAt(stringBuilder.length() - 1, ']');
        return stringBuilder.toString();
    }
}

public class CaInitCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaInitCommand.class);

    private static final String CA_NAME_KEY = "--caname";
    private static final String DN_KEY = "--dn";
    private static final String TOKEN_TYPE_KEY = "--tokenType";
    private static final String TOKEN_PASSWORD_KEY = "--tokenPass";
    private static final String KEY_SPEC_KEY = "--keyspec";
    private static final String KEY_TYPE_KEY = "--keytype";
    private static final String VALIDITY_KEY = "-v";
    private static final String POLICY_ID_KEY = "--policy";
    private static final String SIGNING_ALGORITHM_KEY = "-s";

    private static final String CA_TOKEN_PROPERTIES_KEY = "--tokenprop";
    private static final String CERTIFICATE_PROFILE_KEY = "-certprofile";
    private static final String SUPERADMIN_CN_KEY = "-superadmincn";
    private static final String TYPE_KEY = "-type";
    private static final String EXPLICIT_ECC_KEY = "-explicitecc";
    private static final String SIGNED_BY = "--signedby";
    private static final String EXTERNAL_CHAIN_KEY = "-externalcachain";

    {
        StringBuilder typesStringBuilder = new StringBuilder();
        CaType[] typeArray = CaType.values();
        for (int i = 0; i < typeArray.length; ++i) {
            CaType type = typeArray[i];
            typesStringBuilder.append(type.getTypeName());
            if (i == typeArray.length - 2) {
                typesStringBuilder.append(" or ");
            } else if (i == typeArray.length - 1) {
                break;
            } else {
                typesStringBuilder.append(",");
            }
        }

        StringBuilder availableSignAlgs = new StringBuilder();
        for (String algorithm : AlgorithmConstants.AVAILABLE_SIGALGS) {
            availableSignAlgs.append((availableSignAlgs.length() == 0 ? "" : ", ") + algorithm);
        }

        //Mandatory values
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the CA"));
        registerParameter(new Parameter(DN_KEY, "DN", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "DN"));
        registerParameter(new Parameter(
                TOKEN_TYPE_KEY,
                "Token Type",
                MandatoryMode.MANDATORY,
                StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "Defines if the CA should be created with soft keys or on a HSM. Use 'soft' for software keys and 'org.cesecore.keys.token.PKCS11CryptoToken' for PKCS#11 HSMs."));
        //Password kept as a mandatory argument for legacy reasons
        registerParameter(new Parameter(
                TOKEN_PASSWORD_KEY,
                "Password",
                MandatoryMode.MANDATORY,
                StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "catokenpassword is the password for the CA token. Set to 'null' to use the default system password for Soft token CAs. Set to 'prompt' to prompt for the password on the terminal."));
        registerParameter(new Parameter(KEY_SPEC_KEY, "Key Specification", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Keyspec for RSA keys is size of RSA keys (1024, 2048, 4096, 8192). " + "Keyspec for DSA keys is size of DSA keys (1024). "
                        + "Keyspec for ECDSA keys is name of curve or 'implicitlyCA'' (see docs)."));
        registerParameter(new Parameter(KEY_TYPE_KEY, "Key Type", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Keytype is RSA, DSA or ECDSA."));
        registerParameter(new Parameter(VALIDITY_KEY, "Validity", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Validity of the CA in days."));
        //Policy ID keyt as mandatory parameter for legacy reasons.
        registerParameter(new Parameter(POLICY_ID_KEY, "Policy ID", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "PolicyId can be 'null' if no Certificate Policy extension should be present, or\nobjectID as '2.5.29.32.0' or objectID and cpsurl "
                        + "as \"2.5.29.32.0 http://foo.bar.com/mycps.txt\". You can add multiple policies such as "
                        + "\"2.5.29.32.0 http://foo.bar.com/mycps.txt 1.1.1.1.1 http://foo.bar.com/111cps.txt\"."));
        registerParameter(new Parameter(SIGNING_ALGORITHM_KEY, "Signing Algorithm", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Signing Algorithm may be one of the following: " + availableSignAlgs.toString()));

        //Optional values
        registerParameter(new Parameter(CA_TOKEN_PROPERTIES_KEY, "Filename", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "CA Token properties is a file were you define key name, password and key alias for the HSM. Same as the Hard CA Token Properties in admin gui."));
        registerParameter(new Parameter(CERTIFICATE_PROFILE_KEY, "Profile name", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "Makes the CA use the certificate profile 'profileName' instead of the default ROOTCA or SUBCA."
                        + " Optional parameter that can be completely left out."));
        registerParameter(new Parameter(SUPERADMIN_CN_KEY, "Superadmin CN", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Adding the parameters '-superadmincn SuperAdmin' makes an initial CA use the common name SuperAdmin "
                        + "and initializes the authorization module with an initial super administrator. "
                        + "Note only used when creating initial CA. If parameter is not given, the authorization rules are untouched."));
        registerParameter(new Parameter(TYPE_KEY, "CA Type", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Type is the CA type. May be [" + typesStringBuilder.toString() + "]. Optional parameter, defaults to x509."));
        registerParameter(Parameter.createFlag(EXPLICIT_ECC_KEY, "Adding the switch '" + EXPLICIT_ECC_KEY
                + "' when using ECC keys makes the internal CryptoToken use explicit curve parameters instead of named curves. "
                + "Should only be used when creating a CSCA for ePassports."));
        registerParameter(new Parameter(SIGNED_BY, "CA ID", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                " The ID of a CA that will sign this CA. If this is omitted the new CA will be self signed (i.e. a root CA)."
                        + "To create a CA signed by an external CA, use the keyword 'External' as <CA_ID>, "
                        + "this will result in a certificate request (CSR) being saved on file, to be signed by the external CA. "
                        + "Requires parameter '-externalcachain <externalCA chain PEM file' with the full certificate chain of the external CA."));
        registerParameter(new Parameter(EXTERNAL_CHAIN_KEY, "Certificate Chain File", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "The certificate chain to be used if CA is to be signed by an external CA."));
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        // Install BC provider
        CryptoProviderTools.installBCProviderIfNotAvailable();

        String profileName = parameters.get(CERTIFICATE_PROFILE_KEY);
        final String superAdminCN = parameters.get(SUPERADMIN_CN_KEY);
        //Default is X509
        final CaType type;
        if (parameters.get(TYPE_KEY) != null) {
            type = CaType.lookupCaType(parameters.get(TYPE_KEY));
            if (type == null) {
                log.error("CA type of name " + parameters.get(TYPE_KEY) + " unknown. Available types: " + CaType.getTypeNames());
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        } else {
            type = CaType.X509;
        }
        final String explicitEcc = (parameters.get(EXPLICIT_ECC_KEY) != null ? Boolean.TRUE.toString() : Boolean.FALSE.toString());
        final String extcachainName = parameters.get(EXTERNAL_CHAIN_KEY);

        final String caname = parameters.get(CA_NAME_KEY);
        final String dn = CertTools.stringToBCDNString(StringTools.strip(parameters.get(DN_KEY)));
        final String catokentype = parameters.get(TOKEN_TYPE_KEY);
        String catokenpassword = StringTools.passwordDecryption(parameters.get(TOKEN_PASSWORD_KEY), "ca.tokenpassword");
        if (StringUtils.equals(catokenpassword, "prompt")) {
            getLogger().info("Enter CA token password: ");
            getLogger().info("");
            catokenpassword = String.valueOf(System.console().readPassword());
        }
        final String keyspec = parameters.get(KEY_SPEC_KEY);
        final String keytype = parameters.get(KEY_TYPE_KEY);
        final long validity = Long.parseLong(parameters.get(VALIDITY_KEY));
        String policyId = parameters.get(POLICY_ID_KEY);
        final ArrayList<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
        if ((policyId != null) && (policyId.toLowerCase().trim().equals("null"))) {
            policyId = null;
        } else {
            String[] array = policyId.split(" ");
            for (int i = 0; i < array.length; i += 2) {
                String id = array[i + 0];
                String cpsurl = "";
                if (array.length > i + 1) {
                    cpsurl = array[i + 1];
                }
                policies.add(new CertificatePolicy(id, CertificatePolicy.id_qt_cps, cpsurl));
            }
        }
        String signAlg = parameters.get(SIGNING_ALGORITHM_KEY);
        Properties cryptoTokenProperties = new Properties();
        String caTokenPropertiesFile = parameters.get(CA_TOKEN_PROPERTIES_KEY);
        if (caTokenPropertiesFile != null && "soft".equals(catokentype)) {
            log.error("Can't define a CAToken properties file for a soft token.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } else if (caTokenPropertiesFile != null) {
            if ((caTokenPropertiesFile != null) && (!caTokenPropertiesFile.equalsIgnoreCase("null"))) {
                File file = new File(caTokenPropertiesFile);
                if (!file.exists()) {
                    log.error("CA Token propoerties file " + caTokenPropertiesFile + " does not exist.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                } else if (file.isDirectory()) {
                    log.error("CA Token propoerties file " + caTokenPropertiesFile + " is a directory.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                } else {
                    try {
                        cryptoTokenProperties.load(new FileInputStream(caTokenPropertiesFile));
                    } catch (FileNotFoundException e) {
                        //Can't happen
                        throw new IllegalStateException("Newly referenced file " + caTokenPropertiesFile + " was not found.", e);
                    } catch (IOException e) {
                        throw new IllegalStateException("Unknown exception was caught when reading input stream", e);
                    }
                }
            }
        }
        int signedByCAId = CAInfo.SELFSIGNED;
        if (parameters.get(SIGNED_BY) != null) {
            if (StringUtils.equalsIgnoreCase("External", parameters.get(SIGNED_BY))) {
                signedByCAId = CAInfo.SIGNEDBYEXTERNALCA;
                if (extcachainName == null) {
                    log.error("Signing by external CA requires parameter " + EXTERNAL_CHAIN_KEY);
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            } else {
                signedByCAId = Integer.valueOf(parameters.get(SIGNED_BY));
            }
        }

        // Check that the CA doesn't exist already
        getLogger().debug("Checking that CA doesn't exist: " + caname);
        if (getCAInfo(getAuthenticationToken(), caname) != null) {
            getLogger().error("Error: CA '" + caname + "' exists already");
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        // Get the profile ID from the name if we specified a certain profile name
        int certificateProfileId = CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA;
        if (profileName == null) {
            if (signedByCAId == CAInfo.SELFSIGNED) {
                profileName = "ROOTCA";
            } else {
                profileName = "SUBCA";
                certificateProfileId = CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA;
            }
        } else {
            certificateProfileId = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileId(
                    profileName);
            if (certificateProfileId == 0) {
                getLogger().info("Error: Certificate profile with name '" + profileName + "' does not exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }

            CertificateProfile certificateProfile = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                    .getCertificateProfile(profileName);
            if (certificateProfile.getType() != CertificateConstants.CERTTYPE_ROOTCA
                    && certificateProfile.getType() != CertificateConstants.CERTTYPE_SUBCA) {
                getLogger().info("Error: Certificate profile " + profileName + " is not of type ROOTCA or SUBCA.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }

        if (KeyTools.isUsingExportableCryptography()) {
            getLogger().warn("WARNING!");
            getLogger().warn("WARNING: Using exportable strength crypto!");
            getLogger().warn("WARNING!");
            getLogger().warn(
                    "The Unlimited Strength Crypto policy files have not been installed. EJBCA may not function correctly using exportable crypto.");
            getLogger().warn("Please install the Unlimited Strength Crypto policy files as documented in the Installation guide.");
            getLogger().warn("Sleeping 10 seconds...");
            getLogger().warn("");
            try {
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                throw new IllegalStateException("Thread.sleep was interrupted for unknown reason.", e);
            }
        }
        getLogger().info("Initializing CA");

        getLogger().info("Generating rootCA keystore:");
        getLogger().info("CA Type:" + type.getTypeName());
        getLogger().info("CA name: " + caname);
        getLogger().info("SuperAdmin CN: " + superAdminCN);
        getLogger().info("DN: " + dn);
        getLogger().info("CA token type: " + catokentype);
        getLogger().info("CA token password: " + (catokenpassword == null ? "null" : "hidden"));
        getLogger().info("Keytype: " + keytype);
        getLogger().info("Keyspec: " + keyspec);
        getLogger().info("Validity (days): " + validity);
        getLogger().info("Policy ID: " + policyId);
        getLogger().info("Signature alg: " + signAlg);
        getLogger().info("Certificate profile: " + profileName);
        getLogger().info("CA token properties: " + cryptoTokenProperties.toString());
        if (StringUtils.equalsIgnoreCase(explicitEcc, "true")) {
            // Set if we should use explicit ECC parameters of not. On Java 6 this renders the created CA certificate not serializable
            getLogger().info("Explicit ECC public key parameters: " + explicitEcc);
            cryptoTokenProperties.setProperty(CryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS, explicitEcc);
        }
        try {
            String signedByStr = "Signed by: ";
            if ((signedByCAId != CAInfo.SELFSIGNED) && (signedByCAId != CAInfo.SIGNEDBYEXTERNALCA)) {
                try {
                    CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class)
                            .getCAInfo(getAuthenticationToken(), signedByCAId);
                    signedByStr += cainfo.getName();
                } catch (CADoesntExistsException e) {
                    throw new IllegalArgumentException("CA with id " + signedByCAId + " does not exist.");
                }
            } else if (signedByCAId == CAInfo.SELFSIGNED) {
                signedByStr += "Self signed";
            } else if (signedByCAId == CAInfo.SIGNEDBYEXTERNALCA) {
                signedByStr += "External CA";
            }
            getLogger().info(signedByStr);

            if (superAdminCN != null) {
                try {
                    initAuthorizationModule(getAuthenticationToken(), dn.hashCode(), superAdminCN);
                } catch (RoleExistsException e) {
                    log.error("Tryin to initialize Authorization module (since " + SUPERADMIN_CN_KEY
                            + " was set), but module is already initialized.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            }
            // Transform our mixed properties into CA Token properties and cryptoTokenProperties
            final Properties caTokenProperties = new Properties();
            final String defaultAlias = cryptoTokenProperties.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING);
            if (defaultAlias != null) {
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, defaultAlias);
                cryptoTokenProperties.remove(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING);
            } else {
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
            }
            final String certSignAlias = cryptoTokenProperties.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING);
            if (certSignAlias != null) {
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, certSignAlias);
                cryptoTokenProperties.remove(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING);
            } else {
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            }
            final String crlSignAlias = cryptoTokenProperties.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING);
            if (crlSignAlias != null) {
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, crlSignAlias);
                cryptoTokenProperties.remove(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING);
            } else {
                final String certSignValue = caTokenProperties.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING);
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, certSignValue);
            }
            final String hardTokenEncAlias = cryptoTokenProperties.getProperty(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT_STRING);
            if (hardTokenEncAlias != null) {
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT_STRING, hardTokenEncAlias);
                cryptoTokenProperties.remove(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT_STRING);
            }
            final String keyEncAlias = cryptoTokenProperties.getProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING);
            if (keyEncAlias != null) {
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, keyEncAlias);
                cryptoTokenProperties.remove(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING);
            }
            final String testKeyAlias = cryptoTokenProperties.getProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING);
            if (testKeyAlias != null) {
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, testKeyAlias);
                cryptoTokenProperties.remove(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING);
            }
            // If authentication code is provided as "null", use the default token password for soft tokens (from cesecore.properties), and auto activation
            // If a user defined authentication code is provided, use this and do not enable auto activation for soft tokens
            final char[] authenticationCode;
            if (StringUtils.equalsIgnoreCase(catokenpassword, "null")) {
                authenticationCode = null;
                // auto activation is enabled by default when using the default soft token pwd, which is used by default
            } else {
                authenticationCode = catokenpassword.toCharArray();
            }
            // We must do this in order to not set the default password when creating a new soft CA token
            // A bit tricky, but thats how it is as of EJBCA 5.0.x, 2012-05.
            final String className;
            if (StringUtils.equalsIgnoreCase(catokentype, "soft")) {
                className = SoftCryptoToken.class.getName();
                if (authenticationCode != null) {
                    getLogger().info("Non default password used for soft CA token, auto activation disabled.");
                    cryptoTokenProperties.setProperty(SoftCryptoToken.NODEFAULTPWD, "true");
                }
            } else {
                className = PKCS11CryptoToken.class.getName();
            }
            // Create the CryptoToken
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            int cryptoTokenId;
            try {
                try {
                    cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(getAuthenticationToken(), caname, className,
                            cryptoTokenProperties, null, authenticationCode);
                } catch (CryptoTokenNameInUseException e) {
                    // If the name was already in use we simply add a timestamp to the name to make it unique
                    final String postfix = "_" + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
                    try {
                        cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(getAuthenticationToken(), caname + postfix, className,
                                cryptoTokenProperties, null, authenticationCode);
                    } catch (CryptoTokenNameInUseException e1) {
                        //Shouldn't be able to happen.
                        throw new IllegalStateException("Crypto token name was in use, even though a unique name was just generated.", e);
                    }
                }
            } catch (NoSuchSlotException e) {
                log.error("Slot as defined in the file " + caTokenPropertiesFile + " was not found: " + e.getMessage());
                return CommandResult.FUNCTIONAL_FAILURE;
            } catch (CryptoTokenAuthenticationFailedException e) {
                log.error("Authentication to crypto token failed: " + e.getMessage());
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            // Create the CA Token
            final CAToken caToken = new CAToken(cryptoTokenId, caTokenProperties);
            caToken.setSignatureAlgorithm(signAlg);
            caToken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            // Generate CA keys if it is a soft CryptoToken
            if ("soft".equals(catokentype)) {
                final String signKeyAlias = caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
                final String signKeySpecification = "DSA".equals(keytype) ? "DSA" + keyspec : keyspec;

                try {
                    cryptoTokenManagementSession.createKeyPair(getAuthenticationToken(), cryptoTokenId, signKeyAlias, signKeySpecification);
                } catch (InvalidAlgorithmParameterException e) {
                    log.error(signKeySpecification + " was not a valid alias: " + e.getMessage());
                    return CommandResult.FUNCTIONAL_FAILURE;
                } catch (InvalidKeyException e) {
                    log.error("Key generation for alias " + signKeyAlias + " failed." + e.getMessage());
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
                final String defaultKeyAlias = caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
                // Decryption key must be RSA
                final String defaultKeySpecification = "RSA".equals(keytype) ? keyspec : "2048";
                try {
                    cryptoTokenManagementSession.createKeyPair(getAuthenticationToken(), cryptoTokenId, defaultKeyAlias, defaultKeySpecification);
                } catch (InvalidAlgorithmParameterException e) {
                    log.error(defaultKeySpecification + " was not a valid alias: " + e.getMessage());
                    return CommandResult.FUNCTIONAL_FAILURE;
                } catch (InvalidKeyException e) {
                    log.error("Key generation for alias " + defaultKeyAlias + " failed: " + e.getMessage());
                    return CommandResult.FUNCTIONAL_FAILURE;
                }

            }
            // Create the CA Info
            CAInfo cainfo = null;
            switch (type) {
            case CVC:
                // Get keysequence from SERIALNUMBER in DN is it exists
                final String keysequence = CertTools.getPartFromDN(dn, "SN");
                if (keysequence != null) {
                    getLogger().info("CVC key sequence: " + keysequence);
                    caToken.setKeySequence(keysequence);
                    if (StringUtils.isNumeric(keysequence)) {
                        getLogger().info("CVC key sequence format is numeric.");
                        caToken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
                    } else {
                        getLogger().info("CVC key sequence format is alphanumeric.");
                        caToken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_ALPHANUMERIC);
                    }
                }
                cainfo = createCVCCAInfo(dn, caname, certificateProfileId, validity, signedByCAId, caToken);
                break;
            case X509:
                //Default, slip below.
            default:
                // Create and active OSCP CA Service.
                ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
                String extendedServiceKeySpec = keyspec;
                if (keytype.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
                    // Never use larger keys than 2048 bit RSA for OCSP signing
                    int len = Integer.parseInt(extendedServiceKeySpec);
                    if (len > 2048) {
                        extendedServiceKeySpec = "2048";
                    }
                }
                extendedcaservices.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=CmsCertificate, " + dn, "",
                        extendedServiceKeySpec, keytype));
                extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
                extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
                cainfo = createX509CaInfo(dn, caname, certificateProfileId, validity, signedByCAId, caToken, policies, extendedcaservices);
                break;
            }
            getLogger().info("Creating CA...");
            // Make an error control before starting do do something else.
            List<Certificate> cachain = null;
            if (cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                try {
                    cachain = CertTools.getCertsFromPEM(extcachainName, Certificate.class);
                } catch (CertificateException e) {
                    log.error("Certificate file " + extcachainName + " did not contain a correct certificate.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
                if (cachain == null || cachain.isEmpty()) {
                    log.error(extcachainName + " does not seem to exist or contain any certificates in PEM format.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            }
            try {
                EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).createCA(getAuthenticationToken(), cainfo);
            } catch (CAExistsException e) {
                log.error("CA " + caname + " already exists.");
                return CommandResult.FUNCTIONAL_FAILURE;
            } catch (InvalidAlgorithmException e) {
                log.error("Algirithm was not valid: " + e.getMessage());
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            try {
                if (StringUtils.equalsIgnoreCase(explicitEcc, "true")) {
                    getLogger()
                            .info("Not re-reading CAInfo, since explicit ECC parameters were used, which is not serializable on Java 6. Use Web GUI for further interactions.");
                } else {
                    CAInfo newInfo;

                    newInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caname);

                    int caid = newInfo.getCAId();
                    getLogger().info("CAId for created CA: " + caid);
                }
                if (cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                    getLogger().info("Creating a CA signed by an external CA, creating certificate request.");
                    CAInfo info = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caname);
                    if (info.getStatus() != CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) {
                        log.error("Creating a CA signed by an external CA should result in CA having status, CA_WAITING_CERTIFICATE_RESPONSE. Terminating process, please troubleshoot.");
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                    byte[] request;
                    try {
                        request = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).makeRequest(getAuthenticationToken(),
                                info.getCAId(), cachain, info.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
                    } catch (CertPathValidatorException e) {
                        log.error("Error creating certificate request for CA:" + e.getMessage());
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                    final String filename = info.getName() + "_csr.der";
                    FileOutputStream fos = new FileOutputStream(filename);
                    fos.write(request);
                    fos.close();
                    getLogger().info("Created CSR for CA, to be sent to external CA. Wrote CSR to file '" + filename + "'.");
                } else {
                    getLogger().info("Created and published initial CRL.");
                }
            } catch (CADoesntExistsException e) {
                throw new IllegalStateException("Newly created CA does not exist.", e);
            }
            getLogger().info("CA initialized");
            getLogger().info("Note that any open browser sessions must be restarted to interact with this CA.");
        } catch (AuthorizationDeniedException e) {
            log.error("Current CLI user not authorized to create CA: " + e.getMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (CryptoTokenOfflineException e) {
            log.error("Crypto token was unavailable: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (IOException e) {
            throw new IllegalStateException("Unknown IOException was caught.", e);
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getMainCommand() {
        return "init";
    }

    private CAInfo createX509CaInfo(String dn, String caname, int certificateProfileId, long validity, int signedByCAId, CAToken catokeninfo,
            List<CertificatePolicy> policies, List<ExtendedCAServiceInfo> extendedcaservices) {
        X509CAInfo cainfo = new X509CAInfo(dn, caname, CAConstants.CA_ACTIVE, certificateProfileId, validity,                                             
                signedByCAId, new ArrayList<Certificate>(), catokeninfo);
        cainfo.setDescription(caname + "created using CLI");
        cainfo.setCertificateChain(new ArrayList<Certificate>());
        cainfo.setPolicies(policies);
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        cainfo.setDeltaCRLPeriod(0 * SimpleTime.MILLISECONDS_PER_HOUR);
        return cainfo;
    }

    private CAInfo createCVCCAInfo(String dn, String caname, int certificateProfileId, long validity, int signedByCa, CAToken catokeninfo) {
        CVCCAInfo cainfo = new CVCCAInfo(dn, caname, CAConstants.CA_ACTIVE,
                certificateProfileId, validity, signedByCa, new ArrayList<Certificate>(), catokeninfo);
        cainfo.setDescription("Initial CA");
        return cainfo;
    }

    @Override
    public String getCommandDescription() {
        return "Create a CA and its first CRL. Publishes the CRL and CA certificate";

    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

}
