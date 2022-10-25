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
 
package org.cesecore.util;

import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.util.KeyTools;

import com.keyfactor.util.crypto.algorithm.AlgorithmConfigurationCache;
import com.keyfactor.util.crypto.provider.CryptoProvider;
import com.keyfactor.util.crypto.provider.CryptoProviderRegistry;

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
    private static final String IMPLICITLYCA_Q = AlgorithmConfigurationCache.INSTANCE.getEcDsaImplicitlyCaQ();
    private static final String IMPLICITLYCA_A = AlgorithmConfigurationCache.INSTANCE.getEcDsaImplicitlyCaA();
    private static final String IMPLICITLYCA_B = AlgorithmConfigurationCache.INSTANCE.getEcDsaImplicitlyCaB();
    private static final String IMPLICITLYCA_G = AlgorithmConfigurationCache.INSTANCE.getEcDsaImplicitlyCaG();
    private static final String IMPLICITLYCA_N = AlgorithmConfigurationCache.INSTANCE.getEcDsaImplicitlyCaN();

    /** System provider used to circumvent a bug in Glassfish. Should only be used by 
     * X509CAInfo, OCSPCAService, CMSCAService. 
     * Defaults to SUN but can be changed to IBM by the installBCProvider method.
     */
    public static String SYSTEM_SECURITY_PROVIDER = "SUN";
    
    /**
     * Detect if "Unlimited Strength" Policy files has bean properly installed.
     * 
     * @return true if key strength is limited
     */
    public static boolean isUsingExportableCryptography() {
    	return KeyTools.isUsingExportableCryptography();
    }
    
    public static synchronized void installBCProviderIfNotAvailable() {
    	if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
    		installBCProvider();
    	}
    }

    public static synchronized void removeBCProvider() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);  
        // Also remove other providers, such as the CVC provider
        for(CryptoProvider provider : CryptoProviderRegistry.INSTANCE.getCryptoProviders()) {
            Security.removeProvider(provider.getName());
        }
    }
    
    @SuppressWarnings({ "deprecation", "unchecked" })
    public static synchronized void installBCProvider() {
    	
        // A flag that ensures that we install the parameters for implcitlyCA only when we have installed a new provider
        boolean installImplicitlyCA = false;
        if (Security.addProvider(new BouncyCastleProvider()) < 0) {
        } else {
            installImplicitlyCA = true;
        }
        
    	// Also install non-BC providers, such as the CVC provider
        for(CryptoProvider provider : CryptoProviderRegistry.INSTANCE.getCryptoProviders()) {
            try {
                Security.addProvider(provider.getProvider());            
            } catch (Exception e) {
                log.info(provider.getErrorMessage(), e);
            }
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
        // We must be backwards compatible, i.e. serialNumber is SN in EJBCA
        X509Name.DefaultSymbols.put(X509Name.SN, "SN");
        X500Name.setDefaultStyle(CeSecoreNameStyle.INSTANCE);
        // We hard specify the system security provider in a few cases (see SYSTEM_SECURITY_PROVIDER). 
        // If the SUN provider does not exist, we will always use BC.
        final Provider p = Security.getProvider(SYSTEM_SECURITY_PROVIDER);
        if (p == null) {
        	log.debug("SUN security provider does not exist, using BC as system default provider.");
        	SYSTEM_SECURITY_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
        }
        
    }

}
