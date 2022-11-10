
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
package org.ejbca.core.protocol.cmp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.PBEMacCalculatorProvider;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorProviderBuilder;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Helper class to verify PBMAC1 of CMP messages
 * 
 * @version $Id$
 */
public class CmpPbmac1Verifyer {
	private static final Logger log = Logger.getLogger(CmpPbeVerifyer.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    final PKIMessage msg;
	final private AlgorithmIdentifier pAlg;
	private String errMsg;
	final private String macOid;
	final private int iterationCount;
	private String lastUsedRaSecret;
    final private BigInteger keyLength;
    final private AlgorithmIdentifier prf;
	
	/**
	 * Constructor for CmpPbmac1Verifyer
	 * 
	 * @param msg the PKIMessage payload from the CMP Message
	 * @throws InvalidCmpProtectionException if this class is invoked on a message not signed with a password based MAC or
	 *         the iterator count for this verifier was set higher than 10000.
	 */
	public CmpPbmac1Verifyer(final PKIMessage msg) throws InvalidCmpProtectionException {
        this.msg = msg;
		final PKIHeader head = msg.getHeader();
		this.pAlg = head.getProtectionAlg();
		final ASN1ObjectIdentifier algId = pAlg.getAlgorithm();
		if (!StringUtils.equals(algId.getId(), PKCSObjectIdentifiers.id_PBMAC1.getId())) {
            final String errMsg = "Protection algorithm id expected '"+ PKCSObjectIdentifiers.id_PBMAC1.getId() +
                    "' (PBMAC1) but was '" + algId.getId() + "'.";
            throw new InvalidCmpProtectionException(errMsg);   
		}
		final PBMAC1Params pbmac1Params = PBMAC1Params.getInstance(pAlg.getParameters());
        if (!StringUtils.equals(pbmac1Params.getKeyDerivationFunc().getAlgorithm().getId(), PKCSObjectIdentifiers.id_PBKDF2.getId())) {
            final String errMsg = "Key derivation function id exmpected '" + PKCSObjectIdentifiers.id_PBKDF2 +
                    "' (PBKDF2) but was '" + pbmac1Params.getKeyDerivationFunc().getAlgorithm().getId() + "'.";
            throw new InvalidCmpProtectionException(errMsg);
        }
        final PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(pbmac1Params.getKeyDerivationFunc().getParameters());
        this.iterationCount = pbkdf2Params.getIterationCount().intValue();
        this.keyLength = pbkdf2Params.getKeyLength();
        this.prf = pbkdf2Params.getPrf();
		final AlgorithmIdentifier macAlg = pbmac1Params.getMessageAuthScheme();
		macOid = macAlg.getAlgorithm().getId();
		if (log.isDebugEnabled()) {
			log.debug("Protection type is: " + algId.getId());
			log.debug("Iteration count is: " + iterationCount);
            log.debug("Key length is: " + keyLength);
            log.debug("Prf (psuedo random function) is: " + prf.getAlgorithm().getId());
			log.debug("Mac type is: " + macAlg);
		}
	}
	
	/**
	 * 
	 * @param raAuthenticationSecret the password that should be used to verify the CMP message protection
	 * @return true if the given password was correct
	 * @throws InvalidKeyException if the key was not compatible with this MAC
	 * @throws NoSuchAlgorithmException if the algorithm for the Owf or the MAC weren't found
	 * @throws CMPException if an exception occurs while verifying the MAC
	 */
	public boolean verify(String raAuthenticationSecret) throws InvalidKeyException, NoSuchAlgorithmException, CMPException {
	    if (raAuthenticationSecret == null) {
            throw new IllegalArgumentException("RA authentication secret is null.");
	    }
	    lastUsedRaSecret = raAuthenticationSecret;
		boolean ret = false;
		// Verify the PBMAC1 protection of the message
		if (!pAlg.getAlgorithm().equals(PKCSObjectIdentifiers.id_PBMAC1)) {
			errMsg = intres.getLocalizedMessage("cmp.errorunknownprotalg", pAlg.getAlgorithm().getId());
			log.error(errMsg);
			return ret;
		} else {
            final char[] password = raAuthenticationSecret.toCharArray();
            final ProtectedPKIMessage protectedPkiMessage = new ProtectedPKIMessage(new GeneralPKIMessage(this.msg));
            PBEMacCalculatorProvider macProvider = new JcePBMac1CalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
            ret = protectedPkiMessage.verify(macProvider, password);
		}
		return ret;
	}

	public String getErrMsg() {
		return errMsg;
	}

	public String getMacOid() {
		return macOid;
	}

	public int getIterationCount() {
		return iterationCount;
	}
	
	public String getLastUsedRaSecret() {
		return lastUsedRaSecret;
	}

}
