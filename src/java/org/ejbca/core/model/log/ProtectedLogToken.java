package org.ejbca.core.model.log;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.model.SecConst;

/**
 * Represents the token used for protect-operations of the log events.
 */
public class ProtectedLogToken {

	public static final int TYPE_CA				= 1;
	public static final int TYPE_SYM_KEY		= 2;
	public static final int TYPE_ASYM_KEY	= 3;
	public static final int TYPE_NONE			= 4;
	
	private static final Logger log = Logger.getLogger(ProtectedLogToken.class);

	private ISignSessionLocal signSession = null;
	
	private SecretKey protectionSecretKey = null;
	private PrivateKey protectionPrivateKey = null;
	private PublicKey protectionPublicKey = null;
	private String protectionAlgorithm = null;
	private int caId = -1;
	private Integer tokenIdentifier = null;
	private int tokenType = 0;
	private X509Certificate protectedLogTokenCertificate;
	
	/**
	 * Constructor for symmetric keys. Not implemented yet.
	 */
	public ProtectedLogToken(SecretKey protectionSecretKey, X509Certificate protectedLogTokenCertificate) {
		this.tokenType = TYPE_SYM_KEY;
		this.protectionSecretKey = protectionSecretKey;
		this.protectedLogTokenCertificate = protectedLogTokenCertificate;
		this.protectionAlgorithm = "HmacSHA256";	// TODO: Read this from certificat extension instead when support for symmetric tokens are added
	}

	/**
	 * Constructor for asymmetric keys.
	 */
	public ProtectedLogToken(PrivateKey protectionPrivateKey, X509Certificate protectedLogTokenCertificate) {
		this.tokenType = TYPE_ASYM_KEY;
		this.protectionPublicKey = protectedLogTokenCertificate.getPublicKey();
		this.protectionPrivateKey = protectionPrivateKey;
		this.protectedLogTokenCertificate = protectedLogTokenCertificate;
		this.protectionAlgorithm = protectedLogTokenCertificate.getSigAlgName();
	}
	
	/**
	 * Constructor for CA keys.
	 */
	public ProtectedLogToken(int caId, X509Certificate protectedLogTokenCertificate) {
		this.tokenType = TYPE_CA;
    	this.caId = caId;
		this.protectedLogTokenCertificate = protectedLogTokenCertificate;
    	this.protectionAlgorithm = protectedLogTokenCertificate.getSigAlgName(); 
	}

	public ProtectedLogToken() {
		this.tokenType = TYPE_NONE;
	}

	private ISignSessionLocal getSignSession() {
		try {
			if (signSession == null) {
				signSession = ((ISignSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ISignSessionLocalHome.COMP_NAME)).create();
			}
			return signSession;
		} catch (Exception e) {
			throw new EJBException(e);
		}
	}
	
	public String getProtectionAlgorithm() {
		return protectionAlgorithm;
	}
	
	public int getType() {
		return tokenType;
	}
	
	public X509Certificate getTokenCertificate() {
		return protectedLogTokenCertificate;
	}
	
	public Key getTokenProtectionKey() {
		switch (getType()) {
		case TYPE_ASYM_KEY:
			return protectionPrivateKey;
		case TYPE_SYM_KEY:
			return protectionSecretKey;
		}
		return null;
	}
	
	public int getCAId() {
		return caId;
	}
	
	/**
	 * @return an unique identifier for this ProtectedLogToken. Based on hashing the Key.
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
	
	/**
	 *  Creates a signature based on the tokens properties.
	 */
	public byte[] protect(byte[] data) {
		byte[] signature = null;
		try {
			if (tokenType == TYPE_NONE) {
				// Always return null
			} else if (protectionSecretKey == null && protectionPrivateKey == null) {
				signature = getSignSession().signData(data, caId, SecConst.CAKEYPURPOSE_CERTSIGN);
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
	
	/**
	 *  Verifies a signature based on the tokens properties.
	 *  @return true if the signture matches
	 */
	public boolean verify(byte[] data, byte[] signature) {
		boolean verified = false;
		try {
			if (tokenType == TYPE_NONE) {
				// Never return true
			} else if (protectionSecretKey == null && protectionPublicKey == null) {
				verified = getSignSession().verifySignedData(data, caId, SecConst.CAKEYPURPOSE_CERTSIGN, signature);
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
