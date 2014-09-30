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
 
package org.cesecore.util;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.config.CesecoreConfiguration;
import org.ejbca.cvc.CVCProvider;

/**
 * Basic crypto provider helper methods.
 * 
 * @version $Id$
 */
public final class CryptoProviderTools {
	
	private static final Logger log = Logger.getLogger(CryptoProviderTools.class);
			
    private CryptoProviderTools() {} // Not for instantiation

    /** Parameters used when generating or verifying ECDSA keys/certs using the "implicitlyCA" key encoding.
     * The curve parameters is then defined outside of the key and configured in the BC provider.
     */
    private static final String IMPLICITLYCA_Q = CesecoreConfiguration.getEcdsaImplicitlyCaQ();
    private static final String IMPLICITLYCA_A = CesecoreConfiguration.getEcdsaImplicitlyCaA(); 
    private static final String IMPLICITLYCA_B = CesecoreConfiguration.getEcdsaImplicitlyCaB(); 
    private static final String IMPLICITLYCA_G = CesecoreConfiguration.getEcdsaImplicitlyCaG(); 
    private static final String IMPLICITLYCA_N = CesecoreConfiguration.getEcdsaImplicitlyCaN();

    /** System provider used to circumvent a bug in Glassfish. Should only be used by 
     * X509CAInfo, OCSPCAService, XKMSCAService, CMSCAService. 
     * Defaults to SUN but can be changed to IBM by the installBCProvider method.
     */
    public static String SYSTEM_SECURITY_PROVIDER = "SUN";
    
    /**
     * Detect if "Unlimited Strength" Policy files has bean properly installed.
     * 
     * @return true if key strength is limited
     */
    public static boolean isUsingExportableCryptography() {
    	boolean returnValue = true;
    	try {
    		final int keylen = Cipher.getMaxAllowedKeyLength("DES");
    		if (log.isDebugEnabled()) {
    			log.debug("MaxAllowedKeyLength for DES is: "+keylen);
    		}
			if ( keylen == Integer.MAX_VALUE ) {
				returnValue = false;
			}
		} catch (NoSuchAlgorithmException e) {
			// NOPMD
		}
		return returnValue;
    }
    
    public static synchronized void installBCProviderIfNotAvailable() {
    	if (Security.getProvider("BC") == null) {
    		installBCProvider();
    	}
    }

    public static synchronized void removeBCProvider() {
        Security.removeProvider("BC");  
        // Also remove the CVC provider
        Security.removeProvider("CVC");
    }
    @SuppressWarnings("unchecked")
    public static synchronized void installBCProvider() {
    	
        // A flag that ensures that we install the parameters for implcitlyCA only when we have installed a new provider
        boolean installImplicitlyCA = false;
        if (Security.addProvider(new BouncyCastleProvider()) < 0) {
            // If already installed, remove so we can handle redeploy
            // Nope, we ignore re-deploy on this level, because it can happen
            // that the BC-provider is uninstalled, in just the second another
            // thread tries to use the provider, and then that request will fail.
            if (CesecoreConfiguration.isDevelopmentProviderInstallation()) {
                removeBCProvider();
                if (Security.addProvider(new BouncyCastleProvider()) < 0) {
                    log.error("Cannot even install BC provider again!");
                } else {
                    installImplicitlyCA = true;
                }
            }
        } else {
            installImplicitlyCA = true;
        }
        
    	// Also install the CVC provider
    	try {
        	Security.addProvider(new CVCProvider());    		
    	} catch (Exception e) {
    		log.info("CVC provider can not be installed, CVC certificate will not work: ", e);
    	}
    	
        if (installImplicitlyCA) {
            // Install EC parameters for implicitlyCA encoding of EC keys, we have default curve parameters if no new ones have been given.
            // The parameters are only used if implicitlyCA is used for generating keys, or verifying certs
            final ECCurve curve = new ECCurve.Fp(
                    new BigInteger(IMPLICITLYCA_Q), // q
                    new BigInteger(IMPLICITLYCA_A, 16), // a
                    new BigInteger(IMPLICITLYCA_B, 16)); // b
            final org.bouncycastle.jce.spec.ECParameterSpec implicitSpec = new org.bouncycastle.jce.spec.ECParameterSpec(
                    curve,
                    curve.decodePoint(Hex.decode(IMPLICITLYCA_G)), // G
                    new BigInteger(IMPLICITLYCA_N)); // n
            final ConfigurableProvider config = (ConfigurableProvider)Security.getProvider("BC");
            if (config != null) {
                config.setParameter(ConfigurableProvider.EC_IMPLICITLY_CA, implicitSpec);                                               
            } else {
                log.error("Can not get ConfigurableProvider, implicitlyCA EC parameters NOT set!");
            }                
        }
        
        // 2007-05-25
        // Finally we must configure SERIALNUMBER behavior in BC >=1.36 to be the same
        // as the behavior in BC 1.35, it changed from SN to SERIALNUMBER in BC 1.36
        // We must be backwards compatible
        X509Name.DefaultSymbols.put(X509Name.SN, "SN");
        
        // We hard specify the system security provider in a few cases (see SYSTEM_SECURITY_PROVIDER). 
        // If the SUN provider does not exist, we will always use BC.
        final Provider p = Security.getProvider(SYSTEM_SECURITY_PROVIDER);
        if (p == null) {
        	log.debug("SUN security provider does not exist, using BC as system default provider.");
        	SYSTEM_SECURITY_PROVIDER = "BC";
        }
        
    }

}
