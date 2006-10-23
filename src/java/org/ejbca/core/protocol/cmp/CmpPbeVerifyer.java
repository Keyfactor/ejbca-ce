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

import com.novosec.pkix.asn1.cmp.CMPObjectIdentifiers;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.crmf.PBMParameter;

/**
 * Helper class to verify PBE of CMP messages, also extracts owf, mac Oids and iteration count.
 * @author tomas
 * @version $Id: CmpPbeVerifyer.java,v 1.1 2006-10-23 12:01:32 anatom Exp $
 */
public class CmpPbeVerifyer {
	private static Logger log = Logger.getLogger(CmpPbeVerifyer.class);
	
	private PKIMessage msg = null;
	private String raAuthenticationSecret = null;
	private String errMsg = null;
	private String owfOid = null;
	private String macOid = null;
	private int iterationCount = 1024;
	
	public CmpPbeVerifyer(String key, PKIMessage msg) {
		this.raAuthenticationSecret = key;
		this.msg = msg;
	}
	
	public boolean verify() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		boolean ret = false;
		// Verify the PasswordBased protection of the message
		PKIHeader head = msg.getHeader();
		byte[] protectedBytes = msg.getProtectedBytes();
		DERBitString protection = msg.getProtection();
		AlgorithmIdentifier pAlg = head.getProtectionAlg();
		log.debug("Protection type is: "+pAlg.getObjectId().getId());
		if (!pAlg.getObjectId().equals(CMPObjectIdentifiers.passwordBasedMac)) {
			errMsg = "Received CMP message with unknown protection alg: "+pAlg.getObjectId().getId();
			log.error(errMsg);
			return ret;
		} else {
			PBMParameter pp = PBMParameter.getInstance(pAlg.getParameters());
			iterationCount = pp.getIterationCount().getPositiveValue().intValue();
			log.debug("Iteration count is: "+iterationCount);
			AlgorithmIdentifier owfAlg = pp.getOwf();
			// Normal OWF alg is 1.3.14.3.2.26 - SHA1
			owfOid = owfAlg.getObjectId().getId();
			log.debug("Owf type is: "+owfOid);
			AlgorithmIdentifier macAlg = pp.getMac();
			// Normal mac alg is 1.3.6.1.5.5.8.1.2 - HMAC/SHA1
			macOid = macAlg.getObjectId().getId();
			log.debug("Mac type is: "+macOid);
			byte[] salt = pp.getSalt().getOctets();
			//log.info("Salt is: "+new String(salt));
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
	
}
