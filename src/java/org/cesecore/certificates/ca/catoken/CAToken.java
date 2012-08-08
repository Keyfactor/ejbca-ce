/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca.catoken;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.internal.IUpgradeableData;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.StringTools;

/**
 * Handles operations of the device producing signatures and handling the private key. The SigningCryptoToken interface adds capabilities of handling
 * specific purpose signature and encryption keys, helping the user to choose the right key without having to keep track of the aliases himself.
 * 
 * Based on EJBCA version: ICAToken.java 8828 2010-03-29 08:10:51Z anatom
 * 
 * @version $Id$
 */
public class CAToken extends UpgradeableDataHashMap {

    private static final long serialVersionUID = -459748276141898509L;

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(CAToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**
     * Latest version of the UpgradeableHashMap, this determines if we need to auto-upgrade any data.
     */
    public static final float LATEST_VERSION = 8;

    public static final String CLASSPATH = "classpath";
    public static final String PROPERTYDATA = "propertydata";
    public static final String KEYSTORE = "KEYSTORE";

    public static final String DEFAULT_KEYSEQUENCE = "00000";

    public static final String SOFTPRIVATESIGNKEYALIAS = "privatesignkeyalias";
    public static final String SOFTPREVIOUSPRIVATESIGNKEYALIAS = "previousprivatesignkeyalias";
    public static final String SOFTNEXTPRIVATESIGNKEYALIAS = "nextprivatesignkeyalias";
    public static final String SOFTPRIVATEDECKEYALIAS = "privatedeckeyalias";

    /**
     * Contants for crypto token storage
     */

    /** A sequence for the keys, updated when keys are re-generated */
    public static final String SEQUENCE = "sequence";
    /** Format of the key sequence, the value for this property is one of StringTools.KEY_SEQUENCE_FORMAT_XX */
    public static final String SEQUENCE_FORMAT = "sequenceformat";
    public static final String SIGNATUREALGORITHM = "signaturealgorithm";
    public static final String ENCRYPTIONALGORITHM = "encryptionalgorithm";

    private CryptoToken token;
    private PurposeMapping keyStrings;
    
    public CAToken(final CryptoToken token) {
        super();
        internalInit(token);
    }

	/**
	 * @param token
	 */
	private void internalInit(final CryptoToken token) {
		this.token = token;
        Properties p = token.getProperties();
        this.keyStrings = new PurposeMapping(p);
        setProperties(p);
        setClassPath(token.getClass().getName());
	}

    /** Constructor used to initialize a stored CA token, when the UpgradeableHashMap has been stored as is.
     * 
     * @param data LinkedHashMap
     * @param caid caid that will be token id in the underlying CryptoToken
     * @throws IllegalCryptoTokenException if token properties can not be loaded
     */
    @SuppressWarnings("rawtypes")
    public CAToken(final HashMap tokendata, final int caid) throws IllegalCryptoTokenException {
		loadData(tokendata); 
        final String str = (String) data.get(CAToken.KEYSTORE);
        byte[] keyStoreData = null;
        if (StringUtils.isNotEmpty(str)) {
            keyStoreData = Base64.decode(str.getBytes());
        }
        Properties prop = getProperties();
        final String classpath = (String) data.get(CAToken.CLASSPATH);
        if (log.isDebugEnabled()) {
            log.debug("CA token classpath: " + classpath);
        }
        final CryptoToken token = CryptoTokenFactory.createCryptoToken(classpath, prop, keyStoreData, caid);
        internalInit(token);
    }
    
    public int getTokenStatus() {
        if (log.isTraceEnabled()) {
            log.trace(">getCATokenStatus");
        }
        int ret = CryptoToken.STATUS_OFFLINE;
        // If we have no key aliases, no point in continuing...
        try {
        	if (this.keyStrings != null) {
        		String aliases[] = this.keyStrings.getAliases();
        		int i = 0;
        		// Loop that checks  if there all key aliases have keys
        		while (aliases != null && i < aliases.length) {
        			if (this.token != null && this.token.getKey(aliases[i]) != null) {
        				i++;
        			} else {
        				if (log.isDebugEnabled()) {
        					log.debug("Missing key for alias: "+aliases[i]);
        				}
        			}
        		}
        		// If we don't have any keys for the strings, or we don't have enough keys for the strings, no point in continuing...
        		if (aliases != null && i >= aliases.length) {
        			PrivateKey privateKey;
        			PublicKey publicKey;
        			try {
        				privateKey = getPrivateKey(CATokenConstants.CAKEYPURPOSE_KEYTEST);
        				publicKey = getPublicKey(CATokenConstants.CAKEYPURPOSE_KEYTEST);
        			} catch (CryptoTokenOfflineException e) {
        				privateKey = null;
        				publicKey = null;
        				if (log.isDebugEnabled()) {
        					log.debug("no test key defined");
        				}
        			}
        			if (privateKey != null && publicKey != null) {
        				// Check that that the testkey is usable by doing a test signature.
        				try {
        					token.testKeyPair(privateKey, publicKey);
        					// If we can test the testkey, we are finally active!
        					ret = CryptoToken.STATUS_ACTIVE;
        				} catch (Throwable th) { // NOPMD: we need to catch _everything_ when dealing with HSMs
        					log.error(intres.getLocalizedMessage("token.activationtestfail", token.getId()), th);
        				}
        			}
        		} else {
        			if (log.isDebugEnabled()) {
        				StringBuilder builder = new StringBuilder();
        				for (int j = 0; j < aliases.length; j++) {
        					builder.append(' ').append(aliases[j]);
        				}
        				log.debug("Not enough keys for the key aliases: "+builder.toString());
        			}
        		}
        	}
        } catch (CryptoTokenOfflineException e) {
        	if (log.isDebugEnabled()) {
        		log.debug("CryptToken offline: "+e.getMessage());
        	}
        }

        if (log.isTraceEnabled()) {
        	log.trace("<getCATokenStatus: " + ret);
        }
        return ret;
    }

    /**
     * Updates dynamic properties for the crypto token. Call this method when a new key string, autoactivation PIN has been set and the init method on
     * the crypto token is not called. Does not update properties that is only used when token is created, for example P11 slot, this is only updated
     * on recreation of the token. NOTE: Does not save properties in propertyData
     * 
     * @param properties
     *            Properties containing the new key properties or other properties, such as activation PIN
     */
    private void updateProperties(Properties properties) {
        token.setProperties(properties);
        CATokenInfo info = getTokenInfo();
        info.setProperties(properties);
        this.keyStrings = new PurposeMapping(properties);
    } // updateProperties

    /**
     * Returns the private key (if possible) of token.
     * 
     * @param purpose
     *            should be CATokenConstants.CAKEYPURPOSE_CERTSIGN, CATokenConstants.CAKEYPURPOSE_CRLSIGN or
     *            CATokenConstants.CAKEYPURPOSE_KEYENCRYPT
     * @throws CryptoTokenOfflineException
     *             if Crypto Token is not available or connected.
     * @return PrivateKey object
     */
    public PrivateKey getPrivateKey(final int purpose) throws CryptoTokenOfflineException {
        final String alias = this.keyStrings.getAlias(purpose);
        if (alias == null) {
            throw new CryptoTokenOfflineException("No alias for key purpose " + purpose);
        }
        return token.getPrivateKey(alias);
    }

    /**
     * Returns the public key (if possible) of token.
     * 
     * @param purpose
     *            should be CryptoTokenConstants.CAKEYPURPOSE_CERTSIGN, CryptoTokenConstants.CAKEYPURPOSE_CRLSIGN or
     *            CryptoTokenConstants.CAKEYPURPOSE_KEYENCRYPT
     * @throws CryptoTokenOfflineException
     *             if Crypto Token is not available or connected.
     * @return PublicKey object
     */
    public PublicKey getPublicKey(final int purpose) throws CryptoTokenOfflineException {
        final String alias = this.keyStrings.getAlias(purpose);
        if (log.isTraceEnabled()) {
        	log.trace("Found alias '"+alias+"' for purpose "+purpose);
        	log.trace(keyStrings.toString());
        }
        if (alias == null) {
            throw new CryptoTokenOfflineException("No alias for key purpose " + purpose);
        }
        return token.getPublicKey(alias);
    }

    /**
     * Returns the key label configured for a specific key purpose. Key labels are CATokenConstants.CAKEYPURPOSE_XYZ
     * 
     * @param purpose key purpose from CATokenConstants.CAKEYPURPOSE_ZYX
     * @return an alias of the key in the crypto token, or null of it is not specified in any way, either by the usage constant or by a default constant. 
     */
    public String getKeyLabel(int purpose) {
        return this.keyStrings.getAlias(purpose);
    }

    /*
     * (non Javadoc)
     * @see org.cesecore.keys.token.CryptoToken#getTokenInfo()
     */
    public CATokenInfo getTokenInfo() {
        CATokenInfo info = new CATokenInfo();

        info.setClassPath(getClassPath());
        info.setProperties(getPropertyData());
        setCATokenInfoInternal(info, getSignatureAlgorithm(), getEncryptionAlgorithm(), getKeySequence(), getKeySequenceFormat(), getTokenStatus());

        return info;
    } // getTokenInfo

    /**
     * @param info
     */
    public static void setCATokenInfoInternal(CATokenInfo info, final String signaturealg, final String encryptionalg, final String keysequence,
            final int keysequenceformat, final int status) {
        info.setSignatureAlgorithm(signaturealg);
        info.setEncryptionAlgorithm(encryptionalg);
        info.setKeySequence(keysequence);
        info.setKeySequenceFormat(keysequenceformat);
        // Set status of the CA token
        if (log.isDebugEnabled()) {
        	log.debug("Setting CATokenInfo.status to: " + status);
        }
        info.setTokenStatus(status);
    }

    /**
     * Changes crypto token information, which is the information used to create and initialize the token. CryptoTokenInfo contains, among other
     * things, the properties used to initialize the token itself (such as p11 properties).
     * 
     * @param tokeninfo
     */
    public void updateTokenInfo(CATokenInfo tokeninfo) {

        // We must be able to upgrade class path
        this.setClassPath(token.getClass().getName());

        // Possible to change signature algorithm as well
        String str = tokeninfo.getSignatureAlgorithm();
        if ((str != null) && !StringUtils.equals(getSignatureAlgorithm(), str)) {
            this.setSignatureAlgorithm(str);
        }
        // It is not possible to change encryption algorithm

        Properties newprops = tokeninfo.getProperties();
        if (newprops != null) {
            setProperties(newprops);
            updateProperties(newprops);
        }
        if (tokeninfo.getKeySequence() != null) {
            this.setKeySequence(tokeninfo.getKeySequence());
        }
        this.setKeySequenceFormat(tokeninfo.getKeySequenceFormat());

    } // updateTokenInfo

    public CryptoToken getCryptoToken() {
        return token;
    }

    public void setCryptoToken(final CryptoToken token) {
        this.token = token;
    }

    /**
     * Sets the class path of a CA Token.
     */
    private void setClassPath(String classpath) {
        data.put(CAToken.CLASSPATH, classpath);
    }

    /**
     * Returns the class path of a CA Token.
     */
    private String getClassPath() {
        return (String) data.get(CAToken.CLASSPATH);
    }

    private void setProperties(Properties prop) {
        setPropertyData(storeProperties(prop));
        // Update the properties if we have set new keystrings
        updateProperties(prop);
    }

    /**
     * Internal method just to get rid of the always present date that is part of the standard Properties.store().
     * 
     * @param prop
     * @return String that can be loaded by Properties.load
     */
    private String storeProperties(Properties prop) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(baos);
        Enumeration<Object> e = prop.keys();
        while (e.hasMoreElements()) {
            Object s = e.nextElement();
            if (prop.get(s) != null) {
                writer.println(s + "=" + prop.get(s));
            }
        }
        writer.close();
        return baos.toString();
    }

    /**
     * Sets the propertydata used to configure this CA Token.
     */
    private void setPropertyData(String propertydata) {
        data.put(CAToken.PROPERTYDATA, propertydata);
    }

    /**
     * Returns the propertydata used to configure this Crypto Token.
     */
    private String getPropertyData() {
        String ret = null;
        if (data != null) {
            ret = (String) data.get(CAToken.PROPERTYDATA);
        }
        return ret;
    }
    
    private Properties getProperties() {
        String propertyStr = getPropertyData();
        final Properties prop = new Properties();
        if (StringUtils.isNotEmpty(propertyStr)) {
            try {
				// If the input string contains \ (backslash on windows) we must convert it to \\
				// Otherwise properties.load will parse it as an escaped character, and that is not good
				propertyStr = StringUtils.replace(propertyStr, "\\", "\\\\");
                prop.load(new ByteArrayInputStream(propertyStr.getBytes()));
            } catch (IOException e) {
                log.error("Error getting PCKS#11 token properties: ", e);
            }
        }
        return prop;
    }

    /**
     * Returns the Sequence, that is a sequence that is updated when keys are re-generated
     */
    public String getKeySequence() {
        Object seq = data.get(SEQUENCE);
        if (seq == null) {
            seq = new String(CAToken.DEFAULT_KEYSEQUENCE);
        }
        return (String) seq;
    }

    /**
     * Sets the key sequence
     */
    public void setKeySequence(String sequence) {
        data.put(SEQUENCE, sequence);
    }

    /**
     * Sets the SequenceFormat
     */
    public void setKeySequenceFormat(int sequence) {
        data.put(SEQUENCE_FORMAT, sequence);
    }

    /**
     * Returns the Sequence format, that is the format of the key sequence
     */
    public int getKeySequenceFormat() {
        Object seqF = data.get(SEQUENCE_FORMAT);
        if (seqF == null) {
            seqF = Integer.valueOf(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        }
        return (Integer) seqF;
    }

    /**
     * Returns the SignatureAlgoritm
     */
    private String getSignatureAlgorithm() {
        return (String) data.get(CAToken.SIGNATUREALGORITHM);
    }

    /**
     * Sets the SignatureAlgoritm
     */
    public void setSignatureAlgorithm(String signaturealgoritm) {
        data.put(CAToken.SIGNATUREALGORITHM, signaturealgoritm);
    }

    /**
     * Returns the EncryptionAlgoritm
     */
    private String getEncryptionAlgorithm() {
        return (String) data.get(CAToken.ENCRYPTIONALGORITHM);
    }

    /**
     * Sets the SignatureAlgoritm
     */
    public void setEncryptionAlgorithm(String encryptionalgo) {
        data.put(CAToken.ENCRYPTIONALGORITHM, encryptionalgo);
    }

    /**
     * @see org.cesecore.internal.UpgradeableDataHashMap#getLatestVersion()
     */
    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /**
     * @see org.cesecore.internal.UpgradeableDataHashMap#upgrade()
     */
    @Override
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade
            String msg = intres.getLocalizedMessage("token.upgrade", new Float(getVersion()));
            log.info(msg);

            // Put upgrade stuff here
            if (data.get(CAToken.SEQUENCE_FORMAT) == null) { // v7
                log.info("Adding new sequence format to CA Token data: " + StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
                data.put(CAToken.SEQUENCE_FORMAT, StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            }
            if (data.get(CAToken.SEQUENCE) == null) { // v7
                log.info("Adding new default key sequence to CA Token data: " + CAToken.DEFAULT_KEYSEQUENCE);
                data.put(CAToken.SEQUENCE, CAToken.DEFAULT_KEYSEQUENCE);
            }

            if (data.get(CAToken.CLASSPATH) != null) { // v8 upgrade of classpaths for CESeCore
                final String classpath = (String) data.get(CAToken.CLASSPATH);
                log.info("Upgrading CA token classpath: "+classpath);
                String newclasspath = classpath;
                if (StringUtils.equals(classpath, "org.ejbca.core.model.ca.catoken.SoftCAToken")) {
                	newclasspath = "org.cesecore.keys.token.SoftCryptoToken";
                	// Upgrade properties to set a default key, also for soft crypto tokens
                	Properties prop = getProperties();
                    // A small unfortunate special property that we have to make in order to 
                    // be able to use soft keystores that does not have a specific test or default key
                    if ((prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) &&
                    		(prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null)) {
                    	log.info("Setting CAKEYPURPOSE_CERTSIGN_STRING and CAKEYPURPOSE_CRLSIGN_STRING to privatesignkeyalias.");
                    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
                    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
                    }
                    if ((prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) &&
                    		(prop.getProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING) == null)) {
                    	log.info("Setting CAKEYPURPOSE_DEFAULT_STRING to privatedeckeyalias.");
                    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
                    }
                    setPropertyData(storeProperties(prop)); // Stores property string in "data"
                } else if (StringUtils.equals(classpath, "org.ejbca.core.model.ca.catoken.PKCS11CAToken")) {
                	newclasspath = "org.cesecore.keys.token.PKCS11CryptoToken";
                } else if (StringUtils.equals(classpath, "org.ejbca.core.model.ca.catoken.NullCAToken")) {
                	newclasspath = "org.cesecore.keys.token.NullCryptoToken";
                } else if (StringUtils.equals(classpath, "org.ejbca.core.model.ca.catoken.NFastCAToken")) {
                	log.error("Upgrading of NFastCAToken not supported, you need to convert to using PKCS11CAToken before upgrading.");
                }
                data.put(CAToken.CLASSPATH, newclasspath);
            }

            data.put(VERSION, new Float(LATEST_VERSION));
        }
    }

    private char[] getAuthCodeOrAutoactivationPin(char[] authenticationCode) throws IOException, CryptoTokenAuthenticationFailedException {
        // Generating new keys on token needs an authentication code
        char[] authCode = (authenticationCode != null && authenticationCode.length > 0) ? authenticationCode : null;
        if (authCode == null) {
            String pin = BaseCryptoToken.getAutoActivatePin(token.getProperties());
            if (pin == null) {
                String msg = intres.getLocalizedMessage("token.authcodemissing", token.getId());
                log.info(msg);
                throw new CryptoTokenAuthenticationFailedException(msg);
            }
            authCode = pin.toCharArray();
        }
        return authCode;
    }

    /**
     * Method that generates the keys that will be used by the CAToken. The method can be used to generate keys for an initial CA token or to renew
     * Certificate signing keys. If setstatustowaiting is true and you generate new keys, the new keys will be available as
     * CryptoTokenConstants.CAKEYPURPOSE_CERTSIGN. If setstatustowaiting is false and you generate new keys, the new keys will be available as
     * CryptoTokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT.
     * 
     * @param authenticationCode
     *            the password used to encrypt the keystore, later needed to activate CA Token
     * @param renew
     *            flag indicating if the keys are renewed instead of created fresh. Renewing keys does not create new encryption keys, since this
     *            would make it impossible to decrypt old stuff.
     * @param activate
     *            flag indicating if the new keys should be activated immediately or or they should be added as "next" signing key. Using true here
     *            makes it possible to generate certificate renewal requests for external CAs still using the old keys until the response is received.
     * 
     * @throws CryptoTokenAuthenticationFailedException
     * @throws IOException
     * @throws CryptoTokenOfflineException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * 
     */
    public void generateKeys(final char[] authenticationCode, final boolean renew, final boolean activate)
            throws CryptoTokenAuthenticationFailedException, IOException, CryptoTokenOfflineException, NoSuchAlgorithmException,
            CertificateException, KeyStoreException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException,
            SignatureException {
        if (log.isTraceEnabled()) {
            log.trace(">generateKeys: " + (authenticationCode == null ? "null" : "hidden") + ", renew=" + renew + ", activate=" + activate);
        }
        //
        // Common stuff that should probably be done for all crypto tokens
        //
        // First we start by setting a new sequence for our new keys
        String oldSequence = getKeySequence();
        log.debug("Current sequence: " + oldSequence);
        String newSequence = StringTools.incrementKeySequence(getKeySequenceFormat(), oldSequence);
        // We store the sequence permanently in the object last, when we know everything went well

        // If we don't give an authentication code, perhaps we have autoactivation enabled
        char[] authCode = getAuthCodeOrAutoactivationPin(authenticationCode);

        //
        // End common
        //

        Properties properties = token.getProperties();
        // Current public signature key
        PublicKey pubK = null;
        try {
            pubK = getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        } catch (CryptoTokenOfflineException e) {
            // NOPMD ignore
        }
        String keyLabel = getKeyLabel(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        log.debug("Old key label is: " + keyLabel);
        String crlKeyLabel = getKeyLabel(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
        // The key label to use for the new key
        // Remove the old sequence from the end of the key label and replace it with the
        // new label. If no label was present just concatenate the new label
        String newKeyLabel = keyLabel;
        if (renew) {
        	// If renew is false, we are generating initial keys, and then we don't want to generate a new key label here, 
        	// simply generate the one we have as input
        	// If renew is true, we want to store away the old key label, pointing to an old key, and generate a new key with a new key label
        	newKeyLabel = StringUtils.removeEnd(keyLabel, oldSequence) + newSequence;
        } 
        log.debug("New key label is: " + newKeyLabel);

        // As first choice we check if the used have specified which type of key should be generated, this can be different from the currently used
        // key.
        // If the user did not specify this, we try to generate a key with the same specification as the currently used key.
        String keyspec = properties.getProperty(CryptoToken.KEYSPEC_PROPERTY); // can be null, and that is ok
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(pubK);
        if (log.isDebugEnabled()) {
            String sharedLibrary = properties.getProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY);
            String slot = properties.getProperty(PKCS11CryptoToken.SLOT_LABEL_KEY);
            String attributesFile = properties.getProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY);
            if (keyspec != null) {
                log.debug("Generating new key with specified spec " + keyspec + " with label " + newKeyLabel + ", on slot " + slot
                        + ", using sharedLibrary " + sharedLibrary + ", and attributesFile " + attributesFile);
            } else {
                int keySize = KeyTools.getKeyLength(pubK);
                String alg = pubK.getAlgorithm();
                log.debug("Generating new PKCS#11 " + alg + " key with spec " + paramspec + " (size=" + keySize + ") with label " + newKeyLabel
                        + ", on slot " + slot + ", using sharedLibrary " + sharedLibrary + ", and attributesFile " + attributesFile);
            }
        }
        CryptoToken token = getCryptoToken();
        if (keyspec != null) {
        	// We have to treat DSA specially
        	String sigAlg = getSignatureAlgorithm();
        	if (sigAlg != null) {
            	String keyAlg = AlgorithmTools.getKeyAlgorithmFromSigAlg(sigAlg);
            	if ("DSA".equals(keyAlg) && (!keyspec.startsWith("DSA"))) {
            		keyspec = "DSA"+keyspec;
            	}        		
        	}
            if(log.isDebugEnabled()) {
                log.debug("Generating from string keyspec: " + keyspec);                
            }
            token.generateKeyPair(keyspec, newKeyLabel);
        } else {
            if(log.isDebugEnabled()) {
                log.debug("Generating from AlgorithmParameterSpec: " + paramspec);
            }
            token.generateKeyPair(paramspec, newKeyLabel);
        }
        // Set properties so that we will start using the new key, or not, depending on the activate argument
        PurposeMapping kstr = new PurposeMapping(properties);
        String certsignkeystr = kstr.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        log.debug("CAKEYPURPOSE_CERTSIGN keystring is: " + certsignkeystr);
        String crlsignkeystr = kstr.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
        log.debug("CAKEYPURPOSE_CRLSIGN keystring is: " + crlsignkeystr);
        if (!activate) {
            // If the new keys are not activated we must still use the old key as active signing key (PRIVATESIGNKEYALIAS)
            log.debug("Set nextCertSignKey: " + newKeyLabel);
            properties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, newKeyLabel);
            log.debug("Set next sequence: " + newSequence);
            properties.setProperty(CryptoToken.NEXT_SEQUENCE_PROPERTY, newSequence);
        } else {
            properties.setProperty(certsignkeystr, newKeyLabel);
            // Only set previous sign key, if we have a previous sign key. If the keyLabels are the same, we don't have a 
            // an old key, and so we can of course not have a previous signing key 
            if (!StringUtils.equals(keyLabel, newKeyLabel)) {
                properties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, keyLabel);            	
            }
            // If the key strings are not equal, i.e. crtSignKey and crlSignKey was used instead of just defaultKey
            // and the keys are the same. Then we need to set both keys to use the new key label
            if (!StringUtils.equals(certsignkeystr, crlsignkeystr) && StringUtils.equals(keyLabel, crlKeyLabel)) {
                log.debug("Also setting crlsignkeystr to " + newKeyLabel);
                properties.setProperty(crlsignkeystr, newKeyLabel);
            }
            // Also set the previous sequence
            properties.setProperty(CryptoToken.PREVIOUS_SEQUENCE_PROPERTY, oldSequence);
        }
        // If the renew flag is false, we are generating initial keys for the crypt token
        // In that case we should also generate encryption keys
		if (!renew) {
			log.debug("We are generating initial keys, so see if we should generate an encryption key.");
			// Get the encryption key alias, and if it is not the same as the signature key alias, generate a new key
			// Encryption keys must be RSA, and we force it to be 2048 bit keys, unless the signature keys are smaller,
			// in that case we use the same RSA key size as for signature keys
			String encKeySpec = "2048";
			// For generating initial keys, a keyspec is needed above, so it should not be null here
			if (keyspec != null) {
				try {
					int len = Integer.parseInt(keyspec.trim());
					if (len < 2048) {
						// if less then 2048 used for signature, use same length for key encryption (probably a demo or test CA)
						// Never use larger keys than 2048 bit RSA key for key encryption
						encKeySpec = keyspec;
					}
				} catch (NumberFormatException e) {
					// It was a DSA or ECDSA signature keyspec, use RSA 2048 for encryption keys
					// NOPMD: ignore
				}
			}
	        log.debug("Encryption key spec is: " + encKeySpec);
	        String enckeyLabel = getKeyLabel(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
	        log.debug("CAKEYPURPOSE_KEYENCRYPT key label is: " + enckeyLabel);
	        if (StringUtils.equals(keyLabel, enckeyLabel)) {
	        	log.debug("Key encrypt key alias is same as cert sign key alias, no need to generate specific encryption key.");
	        } else {
	        	log.debug("Key encrypt key alias is not same as cert sign key alias, generating specific encryption key.");
	            token.generateKeyPair(encKeySpec, enckeyLabel);	        	
	        }
		}
        // Store updated properties
        token.setProperties(properties);
        CATokenInfo info = getTokenInfo();
        info.setProperties(properties);
        updateTokenInfo(info);

        // Begin Common stuff to do in the end
        //
        // Store the new sequence permanently. We should not do this earlier, because if an error is thrown generating keys we should not have updated
        // the CA token object
        if (activate) {
            log.debug("Setting new sequence: " + newSequence);
            setKeySequence(newSequence);
        }

        // Finally reset the token so it will be re-read when we want to use it
        // superInit sets properties correctly, just as when reloading the keystore, and activate reloads keys
        // (which are otherwise cached by BaseCryptoToken)
        token.activate(authCode);

        if (log.isDebugEnabled()) {
            String msg = intres.getLocalizedMessage("catoken.generatedkeys", token.getId(), renew, activate);
            log.debug(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<generateKeys");
        }
        //
        // End common stuff to do in the end
        //
    }

    /**
     * Activates the next signing key, if a new signing key has previously been generated and defined as the "next" signing key.
     * 
     * @param authenticationCode
     *            Crypto token authentication code/pin
     * @throws IOException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     * @throws SignatureException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws InvalidKeyException
     * 
     */
    public void activateNextSignKey(char[] authenticationCode) throws CryptoTokenAuthenticationFailedException, IOException,
            CryptoTokenOfflineException, InvalidKeyException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException,
            CertificateException, SignatureException {
        if (log.isTraceEnabled()) {
            log.trace(">activateNextSignKey: " + (authenticationCode == null ? "null" : "hidden"));
        }
        //
        // Common stuff that should probably be done for all crypto tokens
        //
        // First make a check that we have a next sign key

        String oldSequence = getKeySequence();
        log.debug("Current old sequence: " + oldSequence);

        // If we don't give an authentication code, perhaps we have autoactivation enabled
        char[] authCode = getAuthCodeOrAutoactivationPin(authenticationCode);

        Properties properties = token.getProperties();
        //
        // End Common stuff that should probably be done for all crypto tokens
        //

        //
        // Begin Common stuff to do in the end
        //

        // Then we can move on to actually move the keys
        //
        // Activation specific for PKCS#11 tokens
        //
        String nextKeyLabel = getKeyLabel(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
        String currentKeyLabel = getKeyLabel(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        String crlKeyLabel = getKeyLabel(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
        log.debug("Old key label is: " + currentKeyLabel);

        PurposeMapping kstr = new PurposeMapping(properties);
        String certsignkeystr = kstr.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        log.debug("CAKEYPURPOSE_CERTSIGN keystring is: " + certsignkeystr);
        String crlsignkeystr = kstr.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
        log.debug("CAKEYPURPOSE_CRLSIGN keystring is: " + crlsignkeystr);
        log.debug("Setting certsignkeystr to " + nextKeyLabel);
        properties.setProperty(certsignkeystr, nextKeyLabel);
        if (!StringUtils.equals(certsignkeystr, crlsignkeystr) && StringUtils.equals(currentKeyLabel, crlKeyLabel)) {
            log.debug("Also setting crlsignkeystr to " + nextKeyLabel);
            properties.setProperty(crlsignkeystr, nextKeyLabel);
        }
        log.debug("Set previousCertSignKey: " + currentKeyLabel);
        properties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, currentKeyLabel);
        activateKeyFixProperties(oldSequence, properties);
        // Store updated properties
        token.setProperties(properties);
        CATokenInfo info = getTokenInfo();
        info.setProperties(properties);
        updateTokenInfo(info);

        //
        // End specific for PKCS#11 crypto tokens
        //

        // Finally reset the token so it will be re-read when we want to use it
        // superInit sets properties correctly, just as when reloading the keystore, and activate reloads keys
        // (which are otherwise be cached by BaseCryptoToken)
        token.activate(authCode);

        if (log.isDebugEnabled()) {
            String msg = intres.getLocalizedMessage("catoken.activatednextkey", token.getId());
            log.info(msg);
        }
        //
        // End common stuff to do in the end
        //

        if (log.isTraceEnabled()) {
            log.trace("<activateNextSignKey");
        }
    } // activateNextSignKey

    /**
     * Common operation for both soft and hard keystores, move the sequences and remove the NEXT key keystring
     * 
     * @param oldSequence
     *            the old sequence that will be moved to "previous" sequence in the properties
     * @param properties
     *            properties parameter content is modified with new and removed properties
     */
    private void activateKeyFixProperties(String oldSequence, Properties properties) {
        // Set new and previous sequence so we can create link certificates
        String nextSequence = properties.getProperty(CryptoToken.NEXT_SEQUENCE_PROPERTY);
        if (nextSequence != null) {
            log.info("Set key sequence from nextSequence: " + nextSequence);
            setKeySequence(nextSequence);
        }
        log.info("Set previous sequence: " + oldSequence);
        properties.setProperty(CryptoToken.PREVIOUS_SEQUENCE_PROPERTY, oldSequence);
        log.info("Remove nextSequence and nextCertSignKey");
        properties.remove(CryptoToken.NEXT_SEQUENCE_PROPERTY);
        properties.remove(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT);
    } // activateKeyFixProperties

    /**
     * @see IUpgradeableData#saveData()
     */
    @Override
    public Object saveData() {
        byte[] tokendata = token.getTokenData();
        if (tokendata == null) {
            tokendata = new byte[0];
        }
        data.put(CAToken.KEYSTORE, new String(Base64.encode(tokendata)));
        setProperties(token.getProperties());
        return super.saveData();
    }

}
