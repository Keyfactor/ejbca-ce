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

import java.security.Provider;
import java.security.Security;

import com.keyfactor.util.crypto.provider.CryptoProvider;
import com.keyfactor.util.crypto.provider.CryptoProviderRegistry;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.cesecore.keys.util.KeyTools;

/**
 * Basic crypto provider helper methods.
 */
public final class CryptoProviderTools {
	
	private static final Logger log = Logger.getLogger(CryptoProviderTools.class);
			
    private CryptoProviderTools() {} // Not for instantiation

    /** System provider used to circumvent a bug in Glassfish. Should only be used by 
     * X509CAInfo, OCSPCAService. 
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
        Security.removeProvider(BouncyCastlePQCProvider.PROVIDER_NAME);  
        // Also remove other providers, such as the CVC provider
        for(CryptoProvider provider : CryptoProviderRegistry.INSTANCE.getCryptoProviders()) {
            Security.removeProvider(provider.getName());
        }
    }
    
    @SuppressWarnings({ "deprecation", "unchecked" })
    public static synchronized void installBCProvider() {
    	
        // Install the post quantum provider
        if (Security.addProvider(new BouncyCastlePQCProvider()) < 0) {
            log.debug("Cannot install BC PQC provider again!");
        }
        Security.addProvider(new BouncyCastleProvider());
        
    	// Also install non-BC providers, such as the CVC provider
        for(CryptoProvider provider : CryptoProviderRegistry.INSTANCE.getCryptoProviders()) {
            try {
                Security.addProvider(provider.getProvider());            
            } catch (Exception e) {
                log.info(provider.getErrorMessage(), e);
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

    public static String getProviderNameFromAlg(final String alg) {
        if (isPQC(alg)) {
            return BouncyCastlePQCProvider.PROVIDER_NAME;
        }
        return BouncyCastleProvider.PROVIDER_NAME;
    }
    private static final boolean isPQC(String name) {
        if (name == null) {
            return false;
        }
        return StringUtils.startsWithIgnoreCase(name, "FALCON") || name.startsWith("1.3.9999.3")
                || name.equalsIgnoreCase("SPHINCSPLUS") || name.equalsIgnoreCase("SPHINCS+") || name.startsWith(BCObjectIdentifiers.sphincsPlus.getId())
                || StringUtils.startsWithIgnoreCase(name, "DILITHIUM") || name.startsWith("1.3.6.1.4.1.2.267.7")
                || StringUtils.startsWithIgnoreCase(name, "NTRU") || name.startsWith(BCObjectIdentifiers.pqc_kem_ntru.getId())
                || StringUtils.startsWithIgnoreCase(name, "KYBER") || name.startsWith(BCObjectIdentifiers.pqc_kem_kyber.getId());
    }
}
