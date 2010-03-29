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

package org.ejbca.core.model.ca.catoken;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.util.AlgorithmTools;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;
import org.ejbca.util.keystore.KeyStoreContainer;
import org.ejbca.util.keystore.KeyStoreContainerFactory;
import org.ejbca.util.keystore.KeyTools;




/**
 * CATokenContainerImpl is a class managing the persistent storage of a CA token.
 * 
 *
 * @version $Id$
 */
public class CATokenContainerImpl extends CATokenContainer {

    private static final long serialVersionUID = 3363098236866891317L;

    /** Log4j instance */
	private static final Logger log = Logger.getLogger(CATokenContainerImpl.class);
	
	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();

	private ICAToken catoken = null;

    final private int caid; 

	public static final float LATEST_VERSION = 7;


	// Default Values

	protected static final String CLASSPATH                       = "classpath";   
	protected static final String PROPERTYDATA                 = "propertydata";

    /** Class for printing properties (for debug purposes) without revealing any pin properties in the log file
     */
    private class PropertiesWithHiddenPIN extends Properties {

        /**
         * 
         */
        private static final long serialVersionUID = -2240419700704551683L;
        /**
         * 
         */
        public PropertiesWithHiddenPIN() {
        }
        /**
         * @param defaults
         */
        public PropertiesWithHiddenPIN(Properties defaults) {
            super(defaults);
        }
        public synchronized String toString() {
            int max = size() - 1;
            if (max == -1) {
                return "{}";
            }

            final StringBuilder sb = new StringBuilder();
            final Iterator it = entrySet().iterator();

            sb.append('{');
            for (int i = 0; ; i++) {
                final Map.Entry e = (Map.Entry)it.next();
                final String key = (String)e.getKey();
                final String readValue = (String)e.getValue();
                final String value = readValue!=null && readValue.length()>0 && key.trim().equalsIgnoreCase(ICAToken.AUTOACTIVATE_PIN_PROPERTY) ? "xxxx" : readValue;
                sb.append(key);
                sb.append('=');
                sb.append(value);

                if (i == max) {
                    return sb.append('}').toString();
                }
                sb.append(", ");
            }
        }

    }

	/**
	 * 
	 * @param tokentype CATokenInfo.CATOKENTYPE_HSM or similar
	 */
	/**
	 * @param catokeninfo info about the token to be created.
	 * @param _caid unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
	 */
	public CATokenContainerImpl(CATokenInfo catokeninfo, int _caid){
		super();
		this.caid = _caid;
		updateCATokenInfo(catokeninfo);
	}

	/**
	 * @param data that defines the token.
	 * @param _caid unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
	 */
	public CATokenContainerImpl(HashMap data, int _caid) {
        this.caid = _caid;
		loadData(data);  
	}

	// Public Methods    

	/**
	 * Returns the current hardcatoken configuration.
	 */
	public CATokenInfo getCATokenInfo() {
		// First make a call to get the CAToken, so we initialize it
		getCAToken();
		CATokenInfo info = null;
		if (catoken instanceof NullCAToken) {
			info = new NullCATokenInfo();
		}
		String classpath = getClassPath();
		if (catoken instanceof SoftCAToken) {
			SoftCATokenInfo sinfo = new SoftCATokenInfo();
			sinfo.setSignKeySpec((String) data.get(SIGNKEYSPEC));
			sinfo.setSignKeyAlgorithm((String) data.get(SIGNKEYALGORITHM));  
			sinfo.setEncKeySpec((String) data.get(ENCKEYSPEC));
			sinfo.setEncKeyAlgorithm((String) data.get(ENCKEYALGORITHM));  
			sinfo.setEncryptionAlgorithm((String) data.get(ENCRYPTIONALGORITHM));
			if (StringUtils.isEmpty(classpath)) {
				classpath = SoftCAToken.class.getName(); 
			}
			sinfo.setClassPath(classpath);
			info = sinfo;
		} else if (catoken instanceof NullCAToken) {
			NullCATokenInfo ninfo = new NullCATokenInfo();
			info = ninfo;
		} else {
			HardCATokenInfo hinfo = new HardCATokenInfo();
			info = hinfo;
		}		
		info.setClassPath(getClassPath());
		info.setProperties(getPropertyData());
		info.setSignatureAlgorithm(getSignatureAlgorithm());
		info.setKeySequence(getKeySequence());
		info.setKeySequenceFormat(getKeySequenceFormat());

		// Set status of the CA token
		int status = ICAToken.STATUS_OFFLINE;
		if ( catoken != null ){
			status = catoken.getCATokenStatus();
		}
		log.debug("Setting CATokenInfo.status to: "+status);
		info.setCATokenStatus(status);

		return info;
	}

	/**
	 *  Returns the type of CA token, from CATokenConstants.
	 *  @return integer one of CATokenConstants.CATOKENTYPE_XXX, or 0 if we don't know the type
	 *  @see CATokenConstants.CATOKENTYPE_XXX
	 */
	public int getCATokenType() {
		int ret = 0;
		if (data.get(CATOKENTYPE) != null) {
        	ret = (Integer)(data.get(CATOKENTYPE));
		}
		return ret;
	}

	/** 
	 * Updates the hardcatoken configuration
	 */
	public void updateCATokenInfo(CATokenInfo catokeninfo) {

		boolean changed = false;
		// We must be able to upgrade class path
		if (catokeninfo.getClassPath() != null) {
			this.setClassPath(catokeninfo.getClassPath());			
			this.catoken = null;
		}
		// Possible to change signature algorithm as well
		String str = catokeninfo.getSignatureAlgorithm();
		if ( (str != null) && !StringUtils.equals(getSignatureAlgorithm(), str)) {
			this.setSignatureAlgorithm(str);			
			changed = true;
		}

		String props = this.getPropertyData();
		String newprops = catokeninfo.getProperties();
		if ( (newprops != null) && !StringUtils.equals(props, newprops)) {
			this.setPropertyData(newprops);				
			changed = true;
		}
		if (catokeninfo.getKeySequence() != null) {
			this.setKeySequence(catokeninfo.getKeySequence());
		}
        this.setKeySequenceFormat(catokeninfo.getKeySequenceFormat());
		if (catokeninfo instanceof NullCATokenInfo) {
			log.debug("CA Token is CATOKENTYPE_NULL");
			if (data.get(CATOKENTYPE) == null) {
		    	data.put(CATOKENTYPE, new Integer(CATokenConstants.CATOKENTYPE_NULL));
				changed = true;				
			}
		}

		if (catokeninfo instanceof HardCATokenInfo) {
			log.debug("CA Token is CATOKENTYPE_HSM");
			if (data.get(CATOKENTYPE) == null) {
				data.put(CATOKENTYPE, new Integer(CATokenConstants.CATOKENTYPE_HSM));
				changed = true;
			}
		}

		if (catokeninfo instanceof SoftCATokenInfo) {
			log.debug("CA Token is CATOKENTYPE_P12");
			if (data.get(CATOKENTYPE) == null) {
				data.put(CATOKENTYPE, new Integer(CATokenConstants.CATOKENTYPE_P12));
				changed = true;
			}
			SoftCATokenInfo sinfo = (SoftCATokenInfo) catokeninfo;
			// Below for soft CA tokens
			str = sinfo.getSignKeySpec();
			if ( (str != null) && !StringUtils.equals((String)data.get(SIGNKEYSPEC), str)) {
				data.put(SIGNKEYSPEC, str);
				changed = true;
			}
			str = sinfo.getSignKeyAlgorithm();
			if ( (str != null) && !StringUtils.equals((String)data.get(SIGNKEYALGORITHM), str)) {
				data.put(SIGNKEYALGORITHM, str);
				changed = true;
			}
			str = sinfo.getEncKeySpec();
			if ( (str != null) && !StringUtils.equals((String)data.get(ENCKEYSPEC), str)) {
				data.put(ENCKEYSPEC, str);
				changed = true;
			}
			str = sinfo.getEncKeyAlgorithm();
			if ( (str != null) && !StringUtils.equals((String)data.get(ENCKEYALGORITHM), str)) {
				data.put(ENCKEYALGORITHM, str);
				changed = true;
			}
			str = sinfo.getEncryptionAlgorithm();
			if ( (str != null) && !StringUtils.equals((String)data.get(ENCRYPTIONALGORITHM), str)) {
				data.put(ENCRYPTIONALGORITHM, str);
				changed = true;
			}
		}
		if (changed) {
			this.catoken = null;
		}

	}

	/**
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#activate(java.lang.String)
	 */
	public void activate(String authorizationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
		ICAToken token = getCAToken();
		if (token != null) {
			token.activate(authorizationcode);
		} else {
			log.debug("CA token is null and can not be activated.");
		}
	}

	/* (non-Javadoc)
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#deactivate()
	 */
	public boolean deactivate() throws Exception {
		boolean ret = false;
		ICAToken token = getCAToken();
		if (token != null) {
			ret = token.deactivate();
		} else {
			log.debug("CA token is null and does not need deactivation.");
		}
		return ret;
	}


	/**
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#getPrivateKey()
	 */
	public PrivateKey getPrivateKey(int purpose) throws CATokenOfflineException{		
		return getCAToken().getPrivateKey(purpose);
	}

	/**
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#getPublicKey()
	 */
	public PublicKey getPublicKey(int purpose) throws CATokenOfflineException{
		return getCAToken().getPublicKey(purpose);
	}


	/**
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#getProvider()
	 */
	public String getProvider() {		
		return getCAToken().getProvider();
	}
	public String getJCEProvider() {		
		return getCAToken().getJCEProvider();
	}

	/**
	 * Method that generates the keys that will be used by the CAToken.
	 * The method can be used to generate keys for an initial CA token or to renew Certificate signing keys. 
	 * If setstatustowaiting is true and you generate new keys, the new keys will be available as SecConst.CAKEYPURPOSE_CERTSIGN.
	 * If setstatustowaiting is false and you generate new keys, the new keys will be available as SecConst.CAKEYPURPOSE_CERTSIGN_NEXT.
	 * 
	 * @param authenticationCode the password used to encrypt the keystore, later needed to activate CA Token
	 * @param renew flag indicating if the keys are renewed instead of created fresh. Renewing keys does not 
	 * create new encryption keys, since this would make it impossible to decrypt old stuff.
	 * @param activate flag indicating if the new keys should be activated immediately or or they should be added as "next" signing key. 
	 * Using true here makes it possible to generate certificate renewal requests for external CAs still using the old keys until the response is received. 
	 */
	public void generateKeys(String authenticationCode, boolean renew, boolean activate) throws Exception {  
    	if (log.isTraceEnabled()) {
    		log.trace(">generateKeys: "+(authenticationCode == null ? "null":"hidden")+", renew="+renew+", activate="+activate);
    	}
		CATokenInfo catokeninfo = getCATokenInfo();
		
		// First we start by setting a new sequence for our new keys
		String oldSequence = getKeySequence();
		log.debug("Current sequence: "+oldSequence);
		String newSequence = StringTools.incrementKeySequence(getCATokenInfo().getKeySequenceFormat(), oldSequence);
		if (activate) {
			log.debug("Setting new sequence: "+newSequence);
			setKeySequence(newSequence);			
		}
		
		// If we don't give an authentication code, perhaps we have autoactivation enabled
		char[] authCode = getAuthCodeOrAutoactivationPin(authenticationCode);

		String tokentype = null;
		
		// Then we can move on to actually generating the keys
		if (catokeninfo instanceof SoftCATokenInfo) {
			// If we have an existing soft keystore verify that the password is correct
			checkSoftKeystorePassword(authenticationCode);

			SoftCATokenInfo info = (SoftCATokenInfo) catokeninfo;       

			Properties properties = getProperties();

			PublicKey pubEnc = null;
			PrivateKey privEnc = null;
			PublicKey previousPubSign = null;
			PrivateKey previousPrivSign = null;			
			PublicKey oldPreviousPubSign = null;
			PrivateKey oldPreviousPrivSign = null;			
			if (!renew) {
				log.debug("We are generating initial keys.");
				// Generate encryption keys.  
				// Encryption keys must be RSA still
				KeyPair enckeys = KeyTools.genKeys(info.getEncKeySpec(), info.getEncKeyAlgorithm());
				pubEnc = enckeys.getPublic();
				privEnc = enckeys.getPrivate();
			} else {
				log.debug("We are renewing keys.");
				// Get the already existing encryption and signature keys
				ICAToken token = getCAToken();
				pubEnc = token.getPublicKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
				privEnc = token.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
				previousPubSign = token.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
				previousPrivSign = token.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
				oldPreviousPubSign = token.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
				oldPreviousPrivSign = token.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			}
            // As first choice we check if the used have specified which type of key should be generated, this can be different from the currently used key
            // If the user did not specify this, we try to generate a key with the same specification as the currently used key.
			String keyspec = info.getSignKeySpec(); // can be "unknown"
			if (StringUtils.equals(keyspec, AlgorithmTools.KEYSPEC_UNKNOWN)) {
				keyspec = null;
			}
			AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(previousPubSign);					
			if (log.isDebugEnabled()) {
				if (keyspec != null) {
					log.debug("Generating new Soft key with specified spec "+keyspec+" with label "+SoftCAToken.PRIVATESIGNKEYALIAS);						
				} else {
					int keySize = KeyTools.getKeyLength(previousPubSign);
					String alg = previousPubSign.getAlgorithm();
					log.debug("Generating new Soft "+alg+" key with spec "+paramspec+" (size="+keySize+") with label "+SoftCAToken.PRIVATESIGNKEYALIAS);
				}
			}
			// Generate signature keys.
			KeyPair newsignkeys = KeyTools.genKeys(keyspec, paramspec, info.getSignKeyAlgorithm());

			// Create the new keystore and add the new signature keys
			KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
			keystore.load(null, null);

			// PLay with aliases depending on if we activate the new key or not
			String newSignKeyAlias = SoftCAToken.PRIVATESIGNKEYALIAS;
			String previousSignKeyAlias = SoftCAToken.PREVIOUSPRIVATESIGNKEYALIAS;
			if (!activate) {
				// If the new keys are not activated we must still use the old key as active signing key (PRIVATESIGNKEYALIAS)
				newSignKeyAlias = SoftCAToken.NEXTPRIVATESIGNKEYALIAS;
				previousSignKeyAlias = SoftCAToken.PRIVATESIGNKEYALIAS;
			}
			log.debug("Setting newsignkeys as "+newSignKeyAlias+" in soft CA token.");
			Certificate[] certchain = new Certificate[1]; // generate dummy certificate
			String sigAlg = (String)AlgorithmTools.getSignatureAlgorithms(newsignkeys.getPublic()).iterator().next(); 
			certchain[0] = CertTools.genSelfCert("CN=dummy", 36500, null, newsignkeys.getPrivate(), newsignkeys.getPublic(), sigAlg, true);
			keystore.setKeyEntry(newSignKeyAlias, newsignkeys.getPrivate(), null, certchain);
			if (!activate) {
				log.debug("Set next sequence: "+newSequence);
				properties.setProperty(ICAToken.NEXT_SEQUENCE_PROPERTY, newSequence);				
				log.debug("Set nextCertSignKey: "+newSignKeyAlias);
				properties.setProperty(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, newSignKeyAlias);
			}

			// If we have an old key (i.e. generating new keys), we will store the old one as "previous"
			if (previousPrivSign != null) {
				log.debug("Setting previousPrivSign as "+previousSignKeyAlias+" in soft CA token.");
				sigAlg = (String)AlgorithmTools.getSignatureAlgorithms(previousPubSign).iterator().next(); 
				certchain[0] = CertTools.genSelfCert("CN=dummy2", 36500, null, previousPrivSign, previousPubSign, sigAlg, true);				
				keystore.setKeyEntry(previousSignKeyAlias, previousPrivSign, null, certchain);   
				// Now this keystore should have this previous key
				if (activate) {
					// This key pair is now moved down to previous sign key
					properties.setProperty(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, previousSignKeyAlias);					
					// Set previous sequence so we can create link certificates
					log.debug("Set previous sequence : "+oldSequence);
					properties.setProperty(ICAToken.PREVIOUS_SEQUENCE_PROPERTY, oldSequence);
				} else {
					// If we have an old previous key and we are not activating the new key, we will keep this one as "previous"
					// If the new keys are activate the old previous keys are trashed and replaced by the old active signature key
					String prevProp = properties.getProperty(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS); // If we don't have a previous key don't try to add it
					if ( (oldPreviousPrivSign != null) && (prevProp != null) ) {
						log.debug("Setting old previousprivatesignkeyalias as "+SoftCAToken.PREVIOUSPRIVATESIGNKEYALIAS+" in soft CA token.");
						sigAlg = (String)AlgorithmTools.getSignatureAlgorithms(oldPreviousPubSign).iterator().next(); 
						certchain[0] = CertTools.genSelfCert("CN=dummy3", 36500, null, oldPreviousPrivSign, oldPreviousPubSign, sigAlg, true);				
						keystore.setKeyEntry(SoftCAToken.PREVIOUSPRIVATESIGNKEYALIAS, oldPreviousPrivSign, null, certchain);   
						properties.setProperty(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, SoftCAToken.PREVIOUSPRIVATESIGNKEYALIAS);
					} else {
						log.debug("No previousprivatesignkeyalias exists, not setting any previous key.");						
					}
				}
			}
			
			// Finally install the old encryption/decryption keys as well
			sigAlg = (String)AlgorithmTools.getSignatureAlgorithms(pubEnc).iterator().next(); 
			certchain[0] = CertTools.genSelfCert("CN=dummy2", 36500, null, privEnc, pubEnc, sigAlg, true);
			keystore.setKeyEntry(SoftCAToken.PRIVATEDECKEYALIAS, privEnc, null, certchain);	
			
			storeSoftKeyStore(authCode, info, properties, keystore);
			tokentype = "Soft"; // for logging
		} else if (catokeninfo instanceof HardCATokenInfo) {
			ICAToken token = getCAToken();
			if (token instanceof PKCS11CAToken) {
				Properties properties = getProperties();
				PublicKey pubK = token.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
				String keyLabel = token.getKeyLabel(SecConst.CAKEYPURPOSE_CERTSIGN);
				log.debug("Old key label is: "+keyLabel);
				String crlKeyLabel = token.getKeyLabel(SecConst.CAKEYPURPOSE_CRLSIGN);
				// The key label to use for the new key
				// Remove the old sequence from the end of the key label and replace it with the
				// new label. If no label was present just concatenate the new label
				String newKeyLabel = StringUtils.removeEnd(keyLabel, oldSequence)+newSequence;
				log.debug("New key label is: "+newKeyLabel);

				final KeyStore.PasswordProtection pwp = new KeyStore.PasswordProtection(authCode);

	            // As first choice we check if the used have specified which type of key should be generated, this can be different from the currently used key
	            // If the user did not specify this, we try to generate a key with the same specification as the currently used key.
				String keyspec = properties.getProperty(ICAToken.KEYSPEC_PROPERTY); // can be null, and that is ok
				AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(pubK);					
				if (log.isDebugEnabled()) {
					String sharedLibrary = properties.getProperty(PKCS11CAToken.SHLIB_LABEL_KEY);
					String slot = properties.getProperty(PKCS11CAToken.SLOT_LABEL_KEY);
					String attributesFile = properties.getProperty(PKCS11CAToken.ATTRIB_LABEL_KEY);
					if (keyspec != null) {
						log.debug("Generating new PKCS#11 key with specified spec "+keyspec+" with label "+newKeyLabel+", on slot "+slot+", using sharedLibrary "+sharedLibrary+", and attributesFile "+attributesFile);						
					} else {
						int keySize = KeyTools.getKeyLength(pubK);
						String alg = pubK.getAlgorithm();
						log.debug("Generating new PKCS#11 "+alg+" key with spec "+paramspec+" (size="+keySize+") with label "+newKeyLabel+", on slot "+slot+", using sharedLibrary "+sharedLibrary+", and attributesFile "+attributesFile);
					}
				}
				KeyStoreContainer cont = KeyStoreContainerFactory.getInstance(KeyStoreContainer.KEYSTORE_TYPE_PKCS11, token.getProvider(), pwp);
				cont.setPassPhraseLoadSave(authCode);
				if (keyspec != null) {
					log.debug("Generating from string keyspec: "+keyspec);
					cont.generate(keyspec, newKeyLabel);
				} else {
					log.debug("Generating from AlgorithmParameterSpec: "+paramspec);
					cont.generate(paramspec, newKeyLabel);
				}
				// Set properties so that we will start using the new key, or not, depending on the activate argument
				KeyStrings kstr = new KeyStrings(properties);
				String certsignkeystr = kstr.getKey(SecConst.CAKEYPURPOSE_CERTSIGN);
				log.debug("CAKEYPURPOSE_CERTSIGN keystring is: "+certsignkeystr);
				String crlsignkeystr = kstr.getKey(SecConst.CAKEYPURPOSE_CRLSIGN);
				log.debug("CAKEYPURPOSE_CRLSIGN keystring is: "+crlsignkeystr);
				if (!activate) {
					// If the new keys are not activated we must still use the old key as active signing key (PRIVATESIGNKEYALIAS)
					log.debug("Set nextCertSignKey: "+newKeyLabel);
					properties.setProperty(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, newKeyLabel);
					log.debug("Set next sequence: "+newSequence);
					properties.setProperty(ICAToken.NEXT_SEQUENCE_PROPERTY, newSequence);									
				} else {
					properties.setProperty(certsignkeystr, newKeyLabel);
					properties.setProperty(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, keyLabel);
					// If the key strings are not equal, i.e. crtSignKey and crlSignKey was used instead of just defaultKey
					// and the keys are the same. Then we need to set both keys to use the new key label
					if (!StringUtils.equals(certsignkeystr, crlsignkeystr) && StringUtils.equals(keyLabel, crlKeyLabel)) {
						log.debug("Also setting crlsignkeystr to "+newKeyLabel);
						properties.setProperty(crlsignkeystr, newKeyLabel);
					}
					// Also set the previous sequence
					properties.setProperty(ICAToken.PREVIOUS_SEQUENCE_PROPERTY, oldSequence);					
				}
				setProperties(properties);
				tokentype = "PKCS#11"; // for logging
			}
		} else {
			String msg = intres.getLocalizedMessage("catoken.genkeysnotavail");
			log.error(msg);
			return;
		}
		// Finally reset the token so it will be re-read when we want to use it
		this.catoken = null;
		String msg = intres.getLocalizedMessage("catoken.generatedkeys", tokentype);
		log.info(msg);
    	if (log.isTraceEnabled()) {
    		log.trace("<generateKeys");
    	}
	} // generateKeys

	/**
	 * Stores keystore bytes and properties of a soft keystore
	 * @param authenticationCode
	 * @param info
	 * @param properties
	 * @param keystore
	 */
	private void storeSoftKeyStore(char[] authenticationCode,
			SoftCATokenInfo info, Properties properties, KeyStore keystore)
			throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException {
		if (log.isTraceEnabled()) {
			log.trace(">storeSoftKeyStore");
		}
		// Store the key store
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		keystore.store(baos, authenticationCode);
		String ksbytes = new String(Base64.encode(baos.toByteArray()));
		if (log.isDebugEnabled()) {
			log.debug("Storing soft keystore of size "+ksbytes.length());			
		}
		data.put(KEYSTORE, ksbytes);
		data.put(SIGNKEYSPEC, info.getSignKeySpec());
		data.put(SIGNKEYALGORITHM, info.getSignKeyAlgorithm());
		data.put(SIGNATUREALGORITHM, info.getSignatureAlgorithm());
		data.put(ENCKEYSPEC, info.getEncKeySpec());
		data.put(ENCKEYALGORITHM, info.getEncKeyAlgorithm());
		data.put(ENCRYPTIONALGORITHM, info.getEncryptionAlgorithm());
		// Store any changed properties
		if (properties != null) {
			setProperties(properties);			
		}
		if (log.isTraceEnabled()) {
			log.trace("<storeSoftKeyStore");
		}
	} // storeSoftKeyStore

	/** 
	 * 
	 * @throws CATokenAuthenticationFailedException 
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#activateNextSignKey(java.lang.String)
	 */
	public void activateNextSignKey(String authenticationCode) throws CATokenOfflineException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException, CATokenAuthenticationFailedException {
    	if (log.isTraceEnabled()) {
    		log.trace(">activateNextSignKey: "+(authenticationCode == null ? "null":"hidden"));
    	}
		// First make a check that we have a next sign key
		CATokenInfo catokeninfo = getCATokenInfo();

		String oldSequence = getKeySequence();
		log.debug("Current old sequence: "+oldSequence);

		// If we don't give an authentication code, perhaps we have autoactivation enabled
		char[] authCode = getAuthCodeOrAutoactivationPin(authenticationCode);

		Properties properties = getProperties();
		String tokentype = null;

		// Then we can move on to actually move the keys
		if (catokeninfo instanceof SoftCATokenInfo) {
			// If we have an existing soft keystore verify that the password is correct
			checkSoftKeystorePassword(authenticationCode);

			SoftCATokenInfo info = (SoftCATokenInfo) catokeninfo;
			ICAToken token = getCAToken();
			
			PublicKey pubEnc = token.getPublicKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
			PrivateKey privEnc = token.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
			PublicKey pubSign = token.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
			PrivateKey privSign = token.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
			PublicKey nextPubSign = token.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT);
			PrivateKey nextPrivSign = token.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT);
			
			// Create the new keystore and add the new signature keys
			KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
			keystore.load(null, null);
			
			// Insert the old "next" keys into the now active keys
			log.debug("Setting nextPrivSign as "+SoftCAToken.PRIVATESIGNKEYALIAS+" in soft CA token.");
			Certificate[] certchain = new Certificate[1]; // generate dummy certificate
			String sigAlg = (String)AlgorithmTools.getSignatureAlgorithms(nextPubSign).iterator().next(); 
			certchain[0] = CertTools.genSelfCert("CN=dummy", 36500, null, nextPrivSign, nextPubSign, sigAlg, true);
			keystore.setKeyEntry(SoftCAToken.PRIVATESIGNKEYALIAS, nextPrivSign, null, certchain);
			
			// Insert the old active keys into the now "old" keys
			log.debug("Setting privSign as "+SoftCAToken.PREVIOUSPRIVATESIGNKEYALIAS+" in soft CA token.");
			sigAlg = (String)AlgorithmTools.getSignatureAlgorithms(pubSign).iterator().next(); 
			certchain[0] = CertTools.genSelfCert("CN=dummy2", 36500, null, privSign, pubSign, sigAlg, true);				
			keystore.setKeyEntry(SoftCAToken.PREVIOUSPRIVATESIGNKEYALIAS, privSign, null, certchain);   
			properties.setProperty(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, SoftCAToken.PREVIOUSPRIVATESIGNKEYALIAS);
			
			// Finally install the old encryption/decryption keys as well
			sigAlg = (String)AlgorithmTools.getSignatureAlgorithms(pubEnc).iterator().next(); 
			certchain[0] = CertTools.genSelfCert("CN=dummy2", 36500, null, privEnc, pubEnc, sigAlg, true);
			keystore.setKeyEntry(SoftCAToken.PRIVATEDECKEYALIAS, privEnc, null, certchain);	

			activateKeyFixProperties(oldSequence, properties);
			// Serialize and store the soft keystore
			storeSoftKeyStore(authCode, info, properties, keystore);
			tokentype = "Soft"; // for logging
		} else if (catokeninfo instanceof HardCATokenInfo) {
			ICAToken token = getCAToken();
			if (token instanceof PKCS11CAToken) {
				String nextKeyLabel = token.getKeyLabel(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT);
				String currentKeyLabel = token.getKeyLabel(SecConst.CAKEYPURPOSE_CERTSIGN);
				String crlKeyLabel = token.getKeyLabel(SecConst.CAKEYPURPOSE_CRLSIGN);
				log.debug("Old key label is: "+currentKeyLabel);

				KeyStrings kstr = new KeyStrings(properties);
				String certsignkeystr = kstr.getKey(SecConst.CAKEYPURPOSE_CERTSIGN);
				log.debug("CAKEYPURPOSE_CERTSIGN keystring is: "+certsignkeystr);
				String crlsignkeystr = kstr.getKey(SecConst.CAKEYPURPOSE_CRLSIGN);
				log.debug("CAKEYPURPOSE_CRLSIGN keystring is: "+crlsignkeystr);
				log.debug("Setting sertsignkeystr to "+nextKeyLabel);
				properties.setProperty(certsignkeystr, nextKeyLabel);
				if (!StringUtils.equals(certsignkeystr, crlsignkeystr) && StringUtils.equals(currentKeyLabel, crlKeyLabel)) {
					log.debug("Also setting crlsignkeystr to "+nextKeyLabel);
					properties.setProperty(crlsignkeystr, nextKeyLabel);
				}
				log.debug("Set previousCertSignKey: "+currentKeyLabel);
				properties.setProperty(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, currentKeyLabel);
				activateKeyFixProperties(oldSequence, properties);
				// Store updated properties
				setProperties(properties);
				tokentype = "PKCS#11"; // for logging
			}
		}

		// Finally reset the token so it will be re-read when we want to use it
		this.catoken = null;
		String msg = intres.getLocalizedMessage("catoken.activatednextkey", tokentype);
		log.info(msg);

		if (log.isTraceEnabled()) {
    		log.trace("<activateNextSignKey");
    	}
	} // activateNextSignKey

	private char[] getAuthCodeOrAutoactivationPin(String authenticationCode)
			throws IOException, CATokenAuthenticationFailedException {
		// Generating new keys on token needs an authentication code
		char[] authCode = (authenticationCode!=null && authenticationCode.length()>0)? authenticationCode.toCharArray():null;
		if (authCode == null) {
			String pin = BaseCAToken.getAutoActivatePin(getProperties());
			if (pin == null) {
	    		String msg = intres.getLocalizedMessage("catoken.authcodemissing", Integer.valueOf(caid));
	    		log.info(msg);
				throw new CATokenAuthenticationFailedException(msg);
			}
			authCode = pin.toCharArray();
		}
		return authCode;
	}

	/** Verifies the password for soft keystore by trying to load the keystore
	 * 
	 * @param authenticationCode authentication code for the keystore
	 * @throws CATokenAuthenticationFailedException 
	 */
	private void checkSoftKeystorePassword(String authenticationCode) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, CATokenAuthenticationFailedException {
		try {
			if(data.get(CATokenContainer.KEYSTORE) != null){ 
				byte[] ksdata =  Base64.decode(((String) data.get(CATokenContainer.KEYSTORE)).getBytes());
				KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
				keystore.load(new java.io.ByteArrayInputStream(ksdata),authenticationCode.toCharArray());
			}				
		} catch (IOException e) {
			// Invalid password
			String msg = intres.getLocalizedMessage("catoken.wrongauthcode", Integer.valueOf(caid));
			log.info(msg);
			if (!(e instanceof IOException)) {
				// If it was not the wrong password we need to see what went wrong
				log.debug("Error: ", e);
			}
			throw new CATokenAuthenticationFailedException(msg);
		}
	}

	/**
	 * Common operation for both soft and hard keystores, move the sequences and remove the NEXT key keystring
	 * 
	 * @param oldSequence the old sequence that will be moved to "previous" sequence in the properties
	 * @param properties properties parameter content is modified with new and removed properties
	 */
	private void activateKeyFixProperties(String oldSequence, Properties properties) {
		// Set new and previous sequence so we can create link certificates
		String nextSequence = properties.getProperty(ICAToken.NEXT_SEQUENCE_PROPERTY);
		if (nextSequence != null) {
			log.info("Set key sequence from nextSequence: "+nextSequence);
			setKeySequence(nextSequence);
		}
		log.info("Set previous sequence: "+oldSequence);
		properties.setProperty(ICAToken.PREVIOUS_SEQUENCE_PROPERTY, oldSequence);
		log.info("Remove nextSequence and nextCertSignKey");
		properties.remove(ICAToken.NEXT_SEQUENCE_PROPERTY);
		properties.remove(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING_NEXT);
	} // activateKeyFixProperties
	
	/**
	 * Method that import CA token keys from a P12 file. Was originally used when upgrading from 
	 * old EJBCA versions. Only supports SHA1 and SHA256 with RSA or ECDSA and SHA1 with DSA.
	 */
	public void importKeys(String authenticationCode, PrivateKey privatekey, PublicKey publickey, PrivateKey privateEncryptionKey,
			PublicKey publicEncryptionKey, Certificate[] caSignatureCertChain) throws Exception{

		// If we don't give an authentication code, perhaps we have autoactivation enabled
		char[] authCode = getAuthCodeOrAutoactivationPin(authenticationCode);

		// Currently only RSA keys are supported
		KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
		keystore.load(null,null);

		// The CAs certificate is first in chain
		Certificate cacert = caSignatureCertChain[0]; 
		// Assume that the same hash algorithm is used for signing that was used to sign this CA cert
		String signatureAlgorithm = CertTools.getSignatureAlgorithm(cacert);
		String keyAlg = AlgorithmTools.getKeyAlgorithm(publickey);
		if (keyAlg == null) {
			throw new Exception("Unknown public key type: " + publickey.getAlgorithm() + " (" + publickey.getClass() + ")");
		}
		
		// If this is a CVC CA we need to find out the sequence
		if (cacert instanceof CardVerifiableCertificate) {
			CardVerifiableCertificate cvccacert = (CardVerifiableCertificate) cacert;
			log.debug("Getting sequence from holderRef in CV certificate.");
			String sequence = cvccacert.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
			log.debug("Setting sequence "+sequence);
			setKeySequence(sequence);
            log.debug("Setting default sequence format "+StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
			setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
		} else {
			log.debug("Setting default sequence "+CATokenConstants.DEFAULT_KEYSEQUENCE);
			setKeySequence(CATokenConstants.DEFAULT_KEYSEQUENCE);
            log.debug("Setting default sequence format "+StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
		}

		// import sign keys.
		String keyspec = AlgorithmTools.getKeySpecification(publickey);
		Certificate[] certchain = new Certificate[1];
		certchain[0] = CertTools.genSelfCert("CN=dummy", 36500, null, privatekey, publickey, signatureAlgorithm, true);
		
		keystore.setKeyEntry(SoftCAToken.PRIVATESIGNKEYALIAS, privatekey, null, certchain);       

		// generate enc keys.  
		// Encryption keys must be RSA still
		String encryptionSignatureAlgorithm = AlgorithmTools.getEncSigAlgFromSigAlg(signatureAlgorithm);
		keyAlg = AlgorithmTools.getKeyAlgorithmFromSigAlg(encryptionSignatureAlgorithm);
		keyspec = "2048";
		KeyPair enckeys = null;
		if ( publicEncryptionKey == null ||  privateEncryptionKey == null ) {
			enckeys = KeyTools.genKeys(keyspec, keyAlg);
		}
		else {
			enckeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);
		}
		// generate dummy certificate
		certchain[0] = CertTools.genSelfCert("CN=dummy2", 36500, null, enckeys.getPrivate(), enckeys.getPublic(), encryptionSignatureAlgorithm, true);
		keystore.setKeyEntry(SoftCAToken.PRIVATEDECKEYALIAS,enckeys.getPrivate(),null,certchain);              

		// Store keystore
		SoftCATokenInfo info = new SoftCATokenInfo();
		info.setEncKeyAlgorithm(keyAlg);
		info.setEncKeySpec(keyspec);
		info.setEncryptionAlgorithm(encryptionSignatureAlgorithm);
		info.setSignKeyAlgorithm(keyAlg);
		info.setSignKeySpec(keyspec);
		info.setSignatureAlgorithm(signatureAlgorithm);
		storeSoftKeyStore(authCode, info, null, keystore);
		
		// Finally reset the token so it will be re-read when we want to use it
		this.catoken = null;
	} // importKeys

	//
	// Private methods
	//
	/**
	 *  Returns the class path of a CA Token.
	 */    
	private String getClassPath(){
		return (String) data.get(CLASSPATH);
	}

	/**
	 *  Sets the class path of a CA Token.
	 */        
	private void setClassPath(String classpath){
		data.put(CLASSPATH, classpath);	
	}

	/**
	 *  Returns the SignatureAlgoritm
	 */    
	private String getSignatureAlgorithm(){
		return (String) data.get(SIGNATUREALGORITHM);
	}

	/**
	 *  Sets the SignatureAlgoritm
	 */        
	private void setSignatureAlgorithm(String signaturealgoritm){
		data.put(SIGNATUREALGORITHM, signaturealgoritm);	
	}

	/**
	 *  Returns the Sequence, that is a sequence that is updated when keys are re-generated 
	 */    
	private String getKeySequence(){
		Object seq = data.get(SEQUENCE);
		if (seq == null) {
			seq = new String(CATokenConstants.DEFAULT_KEYSEQUENCE);
		}
		return (String)seq;
	}
	
    /**
     *  Sets the key sequence
     */        
    private void setKeySequence(String sequence){
        data.put(SEQUENCE, sequence);   
    }

	/**
	 *  Sets the SequenceFormat
	 */        
	private void setKeySequenceFormat(int sequence){
		data.put(SEQUENCE_FORMAT, sequence);	
	}

    /**
     *  Returns the Sequence format, that is the format of the key sequence
     */    
    private int getKeySequenceFormat(){
        Object seqF = data.get(SEQUENCE_FORMAT);
        if (seqF == null) {
            seqF = new Integer(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        }
        return (Integer)seqF;
    }

	/**
	 *  Returns the propertydata used to configure this CA Token.
	 */    
	private String getPropertyData(){
		String ret = null;
		if (data != null) {
			ret = (String)data.get(PROPERTYDATA);			
		} 
		return ret;
	}

	/**
	 *  Sets the propertydata used to configure this CA Token.
	 */   
	private void setPropertyData(String propertydata){
		data.put(PROPERTYDATA, propertydata);	
	}

	private void setProperties(Properties prop) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		prop.store(baos, null);
		baos.close(); // this has no effect according to javadoc
		setPropertyData(baos.toString());
		// Update the properties if we have set new keystrings
		if (catoken != null) {
			catoken.updateProperties(prop);
		}
	}
	private Properties getProperties() throws IOException{
		Properties prop = new PropertiesWithHiddenPIN();
		String pdata = getPropertyData();
		if (pdata != null) {
			prop.load(new ByteArrayInputStream(pdata.getBytes()));			
		}
		return prop;
	}



	private ICAToken getCAToken() {
		if(catoken == null){
			try{				
				Class implClass = Class.forName( getClassPath());
				Object obj = implClass.newInstance();
				this.catoken = (ICAToken) obj;
				this.catoken.init(getProperties(), data, getSignatureAlgorithm(), this.caid);				
			}catch(Throwable e){
				log.error("Error contructing CA Token (setting to null): ", e);
				catoken = null;
			}
		}

		return catoken;
	}

	//
	// Methods for implementing the UpgradeableDataHashMap
	//

	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#getLatestVersion()
	 */
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}



	public void upgrade() {
		if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
			// New version of the class, upgrade
			String msg = intres.getLocalizedMessage("catoken.upgrade", new Float(getVersion()));
			log.info(msg);
			if(data.get(SIGNKEYALGORITHM) == null) {
				String oldKeyAlg = (String)data.get(KEYALGORITHM); 
				if (oldKeyAlg != null) {
					data.put(SIGNKEYALGORITHM, oldKeyAlg);
					data.put(ENCKEYALGORITHM, oldKeyAlg);					
				}
			}            
			if(data.get(SIGNKEYSPEC) == null) {
				Integer oldKeySize = ((Integer) data.get(KEYSIZE));
				if (oldKeySize != null) {
					data.put(SIGNKEYSPEC, oldKeySize.toString());
					data.put(ENCKEYSPEC, oldKeySize.toString());					
				}
			}
			if(data.get(ENCRYPTIONALGORITHM) == null) {
				String signAlg = (String)data.get(SIGNATUREALGORITHM);            	
				data.put(ENCRYPTIONALGORITHM, signAlg);
			}
			if (data.get(CLASSPATH) == null) {
				String classpath = SoftCAToken.class.getName();
				if (data.get(KEYSTORE) == null) {
					classpath = NullCAToken.class.getName();
				}
				log.info("Adding new classpath to CA Token data: "+classpath);
				data.put(CLASSPATH, classpath);
			}

			if (data.get(SEQUENCE) == null) {
				String sequence = CATokenConstants.DEFAULT_KEYSEQUENCE;
				log.info("Adding new sequence to CA Token data: "+sequence);
				data.put(SEQUENCE, sequence);
			}

			if (data.get(SEQUENCE_FORMAT) == null) { // v7
				log.info("Adding new sequence format to CA Token data: "+StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
				data.put(SEQUENCE_FORMAT, StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
			}

			data.put(VERSION, new Float(LATEST_VERSION));
		}  		
	}


}
