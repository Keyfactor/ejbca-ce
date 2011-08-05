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
package org.ejbca.core.protocol.cmp;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.ejbca.core.model.InternalResources;

import com.novosec.pkix.asn1.cmp.CMPObjectIdentifiers;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.crmf.PBMParameter;

/**
 * Helper class to verify PBE of CMP messages, also extracts owf, mac Oids and iteration count.
 * @author tomas
 * @version $Id$
 */
public class CmpPbeVerifyer {
	private static final Logger LOG = Logger.getLogger(CmpPbeVerifyer.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    private byte[] protectedBytes = null;
    private DERBitString protection = null;
	private AlgorithmIdentifier pAlg = null;
	private String errMsg = null;
	private String owfOid = null;
	private String macOid = null;
	private int iterationCount = 1024;
	private byte[] salt = null;
	private String lastUsedRaSecret = null;
	
	public CmpPbeVerifyer(PKIMessage msg) {
		PKIHeader head = msg.getHeader();
		protectedBytes = msg.getProtectedBytes();
		protection = msg.getProtection();
		pAlg = head.getProtectionAlg();
		PBMParameter pp = PBMParameter.getInstance(pAlg.getParameters());
		iterationCount = pp.getIterationCount().getPositiveValue().intValue();
		AlgorithmIdentifier owfAlg = pp.getOwf();
		// Normal OWF alg is 1.3.14.3.2.26 - SHA1
		owfOid = owfAlg.getObjectId().getId();
		AlgorithmIdentifier macAlg = pp.getMac();
		// Normal mac alg is 1.3.6.1.5.5.8.1.2 - HMAC/SHA1
		macOid = macAlg.getObjectId().getId();
		if (LOG.isDebugEnabled()) {
			LOG.debug("Protection type is: "+pAlg.getObjectId().getId());
			LOG.debug("Iteration count is: "+iterationCount);
			LOG.debug("Owf type is: "+owfOid);
			LOG.debug("Mac type is: "+macOid);
		}
		salt = pp.getSalt().getOctets();
		//log.info("Salt: "+new String(salt));
	}
	
	public boolean verify(String raAuthenticationSecret) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		lastUsedRaSecret = raAuthenticationSecret;
		boolean ret = false;
		// Verify the PasswordBased protection of the message
		if (!pAlg.getObjectId().equals(CMPObjectIdentifiers.passwordBasedMac)) {
			errMsg = INTRES.getLocalizedMessage("cmp.errorunknownprotalg", pAlg.getObjectId().getId());
			LOG.error(errMsg);
			return ret;
		} else {
			if (iterationCount > 10000) {
				LOG.info("Received message with too many iterations in PBE protection: "+iterationCount);
				throw new InvalidKeyException("Iteration count can not exceed 10000");
			}			
			byte[] raSecret = raAuthenticationSecret.getBytes();
			byte[] basekey = new byte[raSecret.length + salt.length];
			for (int i = 0; i < raSecret.length; i++) {
				basekey[i] = raSecret[i];
			}
			for (int i = 0; i < salt.length; i++) {
				basekey[raSecret.length+i] = salt[i];
			}
			// Construct the base key according to rfc4210, section 5.1.3.1
			MessageDigest dig = MessageDigest.getInstance(owfOid, "BC");
			for (int i = 0; i < iterationCount; i++) {
				basekey = dig.digest(basekey);
				dig.reset();
			}
			// HMAC/SHA1 is normal 1.3.6.1.5.5.8.1.2 or 1.2.840.113549.2.7 
			Mac mac = Mac.getInstance(macOid, "BC");
			SecretKey key = new SecretKeySpec(basekey, macOid);
			mac.init(key);
			mac.reset();
			mac.update(protectedBytes, 0, protectedBytes.length);
			byte[] out = mac.doFinal();
			// My out should now be the same as the protection bits
			byte[] pb = protection.getBytes();
			ret = Arrays.equals(out, pb);
		}
		return ret;
	}

	public String getErrMsg() {
		return errMsg;
	}

	public String getMacOid() {
		return macOid;
	}

	public String getOwfOid() {
		return owfOid;
	}

	public int getIterationCount() {
		return iterationCount;
	}
	
	public String getLastUsedRaSecret() {
		return lastUsedRaSecret;
	}
	
}
