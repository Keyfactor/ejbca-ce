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
package org.ejbca.core.model.log;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CACacheManager;
import org.ejbca.core.model.ca.catoken.CATokenContainer;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Represents the token used for protect-operations of the log events.
 * @version $Id$
 * @deprecated
 */
public class ProtectedLogToken implements IProtectedLogToken {

	private static final Logger log = Logger.getLogger(ProtectedLogToken.class);

	private SecretKey protectionSecretKey = null;
	private PrivateKey protectionPrivateKey = null;
	private PublicKey protectionPublicKey = null;
	private String protectionAlgorithm = null;
	private int caId = -1;
	private Integer tokenIdentifier = null;
	private int tokenType = 0;
	private Certificate protectedLogTokenCertificate;
	
	/**
	 * Constructor for symmetric keys. Not implemented yet.
	 */
	public ProtectedLogToken(SecretKey protectionSecretKey, Certificate protectedLogTokenCertificate) {
		this.tokenType = TYPE_SYM_KEY;
		this.protectionSecretKey = protectionSecretKey;
		this.protectedLogTokenCertificate = protectedLogTokenCertificate;
		this.protectionAlgorithm = "HmacSHA256";	// TODO: Read this from certificat extension instead when support for symmetric tokens are added
	}

	/**
	 * Constructor for asymmetric keys.
	 */
	public ProtectedLogToken(PrivateKey protectionPrivateKey, Certificate protectedLogTokenCertificate) {
		this.tokenType = TYPE_ASYM_KEY;
		this.protectionPublicKey = protectedLogTokenCertificate.getPublicKey();
		this.protectionPrivateKey = protectionPrivateKey;
		this.protectedLogTokenCertificate = protectedLogTokenCertificate;
		this.protectionAlgorithm = CertTools.getSignatureAlgorithm(protectedLogTokenCertificate);
	}
	
	/**
	 * Constructor for CA keys.
	 */
	public ProtectedLogToken(int caId, Certificate protectedLogTokenCertificate) {
		this.tokenType = TYPE_CA;
    	this.caId = caId;
		this.protectedLogTokenCertificate = protectedLogTokenCertificate;
		this.protectionAlgorithm = CertTools.getSignatureAlgorithm(protectedLogTokenCertificate);
	}

	public ProtectedLogToken() {
		this.tokenType = TYPE_NONE;
	}

	/* (non-Javadoc)
	 * @see org.ejbca.core.model.log.IProtectedLogToken#getProtectionAlgorithm()
	 */
	public String getProtectionAlgorithm() {
		return protectionAlgorithm;
	}
	
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.log.IProtectedLogToken#getType()
	 */
	public int getType() {
		return tokenType;
	}
	
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.log.IProtectedLogToken#getTokenCertificate()
	 */
	public Certificate getTokenCertificate() {
		return protectedLogTokenCertificate;
	}
	
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.log.IProtectedLogToken#getTokenProtectionKey()
	 */
	public Key getTokenProtectionKey() {
		switch (getType()) {
		case TYPE_ASYM_KEY:
			return protectionPrivateKey;
		case TYPE_SYM_KEY:
			return protectionSecretKey;
		}
		return null;
	}
	
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.log.IProtectedLogToken#getCAId()
	 */
	public int getCAId() {
		return caId;
	}
	
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.log.IProtectedLogToken#getIdentifier()
	 */
	public int getIdentifier() {
		if (tokenIdentifier == null) {
			byte[] keyData = null;
			if (protectionSecretKey != null) {
				keyData = protectionSecretKey.getEncoded();
			} else if (protectionPublicKey != null) {
				keyData = protectionPublicKey.getEncoded();
			} else if (tokenType == TYPE_CA) {
				keyData = protectedLogTokenCertificate.getPublicKey().getEncoded();
			}
			if (tokenType != TYPE_NONE) {
				// Hash it and create an integer from the first four byte, MSB in first position
				MessageDigest messageDigest;
				try {
					// If this hash-algo is somewhat broken it's not the end of the world since only the first four bytes are used.
					messageDigest = MessageDigest.getInstance("SHA-256", "BC");
				} catch (NoSuchAlgorithmException e) {
					throw new EJBException(e);
				} catch (NoSuchProviderException e) {
					throw new EJBException(e);
				}
				byte[] digest = messageDigest.digest(keyData);
				tokenIdentifier = new Integer( ((digest[0] << 24) & 0xff000000) | ((digest[1] << 16) & 0x00ff0000) | ((digest[2] << 8) & 0x0000ff00) | (digest[3] & 0x000000ff) );
			} else {
				tokenIdentifier = new Integer(0);
			}
		}
		return tokenIdentifier;
	}
	
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.log.IProtectedLogToken#protect(byte[])
	 */
	public byte[] protect(byte[] data) {
		byte[] signature = null;
		try {
			if (tokenType == TYPE_NONE) {
				// Always return null
			} else if (protectionSecretKey == null && protectionPrivateKey == null) {
		        CA ca = CACacheManager.instance().getCA(caId, null);
		        if (ca == null) {
		        	log.error("CA not found.");
		        } else {
			        CATokenContainer caToken = ca.getCAToken(); 
			        String signatureAlgorithm = ca.getCAInfo().getCATokenInfo().getSignatureAlgorithm();
			        PrivateKey privateKey = caToken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
			        signature = KeyTools.signData(privateKey, signatureAlgorithm, data);
				}
			} else if (protectionPrivateKey != null) {
				Signature signer = Signature.getInstance(protectionAlgorithm, "BC");
				signer.initSign(protectionPrivateKey);
				signer.update(data);
				signature = signer.sign();
			} else if (protectionSecretKey != null) {
				Mac mac = Mac.getInstance(protectionAlgorithm, "BC");
				mac.init(protectionSecretKey);
				signature = mac.doFinal(data);
			}
		} catch (Exception e) {
			log.error(e);
		}
		return signature;
	}
	
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.log.IProtectedLogToken#verify(byte[], byte[])
	 */
	public boolean verify(byte[] data, byte[] signature) {
		boolean verified = false;
		try {
			if (tokenType == TYPE_NONE) {
				// Never return true
			} else if (protectionSecretKey == null && protectionPublicKey == null) {
		        CA ca = CACacheManager.instance().getCA(caId, null);
		        if (ca == null) {
		        	log.error("CA not found.");
		        }
		        CATokenContainer caToken = ca.getCAToken(); 
		        String signatureAlgorithm = ca.getCAInfo().getCATokenInfo().getSignatureAlgorithm();
		        PublicKey publicKey = caToken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		        verified = KeyTools.verifyData(publicKey, signatureAlgorithm, data, signature);
			} else if (protectionPublicKey != null) {
				Signature signer = Signature.getInstance(protectionAlgorithm, "BC");
				signer.initVerify(protectionPublicKey);
				signer.update(data);
				verified = signer.verify(signature);
			} else if (protectionSecretKey != null) {
				Mac mac = Mac.getInstance(protectionAlgorithm, "BC");
				mac.init(protectionSecretKey);
				verified = Arrays.equals(signature, mac.doFinal(data));
			}
		} catch (Exception e) {
			log.error(e);
		}
		return verified;
	}
}
