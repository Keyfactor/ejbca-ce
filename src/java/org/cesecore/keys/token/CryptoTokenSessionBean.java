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
package org.cesecore.keys.token;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;

/**
 * Based on CESeCore version:
 *      CryptoTokenSessionBean.java 897 2011-06-20 11:17:25Z johane
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CryptoTokenSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CryptoTokenSessionBean implements CryptoTokenSessionLocal, CryptoTokenSessionRemote {

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @EJB
    private SecurityEventsLoggerSessionLocal securityLogger;

    @Override
	public CryptoToken createCryptoToken(final AuthenticationToken admin, final String classname, final Properties properties, final byte[] data, final int id) {
    	CryptoToken token = CryptoTokenFactory.createCryptoToken(classname, properties, data, id);

    	String msg = intres.getLocalizedMessage("token.createdtoken", classname, id);
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        securityLogger.log(EventTypes.CRYPTOTOKEN_CREATE, EventStatus.SUCCESS, ModuleTypes.KEY_MANAGEMENT, ServiceTypes.CORE,admin.toString(), null, null, null, details);

    	return token;
    }

    @Override
    public CryptoToken deleteEntry(final AuthenticationToken admin, CryptoToken token, char[] authenticationcode, String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
    	token.activate(authenticationcode);
    	token.deleteEntry(authenticationcode, alias);

    	String msg = intres.getLocalizedMessage("token.deleteentry", alias, token.getId());
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        securityLogger.log(EventTypes.CRYPTOTOKEN_DELETE_ENTRY, EventStatus.SUCCESS, ModuleTypes.KEY_MANAGEMENT, ServiceTypes.CORE,admin.toString(), null, null, null, details);

        return token;
    }

    @Override
    public CryptoToken generateKeyPair(final AuthenticationToken admin, final CryptoToken token, final char[] authenticationcode, final String keySpec, final String alias) throws NoSuchAlgorithmException,
		NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, KeyStoreException,
		CertificateException, IOException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
    	token.activate(authenticationcode);
    	token.generateKeyPair(keySpec, alias);

        PublicKey pb = token.getPublicKey(alias);

    	String msg = intres.getLocalizedMessage("token.generatedkeypair", keySpec, alias, token.getId());
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        details.put("publicKey", new String(Base64.encode(pb.getEncoded())));

        EventType event = token.doPermitExtractablePrivateKey() ? EventTypes.CRYPTOTOKEN_GEN_EXTRACT_KEYPAIR : EventTypes.CRYPTOTOKEN_GEN_KEYPAIR;
        securityLogger.log(event, EventStatus.SUCCESS, ModuleTypes.KEY_MANAGEMENT, ServiceTypes.CORE,admin.toString(), null, null, null, details);

        return token;
    }

    @Override
    public CryptoToken generateKeyPair(final AuthenticationToken admin, final CryptoToken token, final char[] authenticationcode, final PublicKey template, final String alias) throws NoSuchAlgorithmException,
	    NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, KeyStoreException,
	    CertificateException, IOException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
    	token.activate(authenticationcode);
    	AlgorithmParameterSpec spec = KeyTools.getKeyGenSpec(template);
    	token.generateKeyPair(spec, alias);

        PublicKey pb = token.getPublicKey(alias);

    	String msg = intres.getLocalizedMessage("token.generatedkeypair", spec.getClass(), alias, token.getId());
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        details.put("publicKey", new String(Base64.encode(pb.getEncoded())));

        EventType event = token.doPermitExtractablePrivateKey() ? EventTypes.CRYPTOTOKEN_GEN_EXTRACT_KEYPAIR : EventTypes.CRYPTOTOKEN_GEN_KEYPAIR;
        securityLogger.log(event, EventStatus.SUCCESS, ModuleTypes.KEY_MANAGEMENT, ServiceTypes.CORE,admin.toString(), null, null, null, details);

        return token;
    }

    @Override
    public CryptoToken generateKey(final AuthenticationToken admin, final CryptoToken token, final char[] authenticationcode, final String algorithm, final int keysize, final String alias) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CryptoTokenOfflineException,
    InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException, CryptoTokenAuthenticationFailedException {
    	token.activate(authenticationcode);
    	token.generateKey(algorithm, keysize, alias);

    	String msg = intres.getLocalizedMessage("token.generatedsymkey", algorithm, keysize, alias, token.getId());
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        securityLogger.log(EventTypes.CRYPTOTOKEN_GEN_KEY, EventStatus.SUCCESS, ModuleTypes.KEY_MANAGEMENT, ServiceTypes.CORE,admin.toString(), null, null, null, details);

        return token;
    }

}
