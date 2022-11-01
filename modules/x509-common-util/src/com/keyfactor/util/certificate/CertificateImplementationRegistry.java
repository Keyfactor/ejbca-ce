/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.certificate;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.keyfactor.util.certificate.x509.X509CertificateUtility;

/**
 *
 */
public enum CertificateImplementationRegistry {
    INSTANCE;
    
    private final Map<String, CertificateImplementation> certificateImplementations = new HashMap<>();
    
    private final Map<Class<?>, CertificateImplementation> certificateImplementationsByClassType = new HashMap<>();
    
    private CertificateImplementationRegistry() {
        for (CertificateImplementation certificateImplementation : ServiceLoader.load(CertificateImplementation.class)) {
            addCertificateImplementation(certificateImplementation);
        }
        //Since X509 exists locally. always add it 
        if(!certificateImplementationsByClassType.containsKey(X509Certificate.class)) {
            addCertificateImplementation(new X509CertificateUtility());
        }
    }
    
    /**
     * Primarily for use in unit testing. Implementations should normally be added automatically in the constructor. 
     */
    public void addCertificateImplementation(final CertificateImplementation certificateImplementation) {
        certificateImplementations.put(certificateImplementation.getType(), certificateImplementation);
        certificateImplementationsByClassType.put(certificateImplementation.getImplementationClass(), certificateImplementation);
    }
    
    public CertificateImplementation getCertificateImplementation(final String name) {
        return certificateImplementations.get(name);
    }
    
    public CertificateImplementation getCertificateImplementation(final Class<?> clazz) {
        return certificateImplementationsByClassType.get(clazz);
    }
    
    /**
     * Creates Certificate from byte[], can be either an X509 certificate or a CVCCertificate
     * 
     * @param cert byte array containing certificate in binary (DER) format, or PEM encoded X.509 certificate
     * @param provider provider for example "SUN" or "BC", use null for the default provider (BC)
     * @param returnType the type of Certificate to be returned. Certificate can be used if certificate type is unknown.
     * 
     * @return a Certificate 
     * @throws CertificateParsingException if certificate couldn't be parsed from cert, or if the incorrect return type was specified.
     * 
     */
    public <T extends Certificate> T getCertfromByteArray(byte[] cert, String provider, Class<T> returnType) throws CertificateParsingException {
        String prov = provider;
        if (provider == null) {
            prov = BouncyCastleProvider.PROVIDER_NAME;
        }   
        CertificateImplementation certificateImplementation = getCertificateImplementation(returnType);
        if (certificateImplementation != null) {
            return returnType.cast(certificateImplementation.parseCertificate(provider, cert));
        } else {
            if (certificateImplementations.size() != 0) {
                //If no parser is found due to unclear return type, let's try everything.
                for (CertificateImplementation implementation : certificateImplementations.values()) {
                    try {
                        return returnType.cast(implementation.parseCertificate(prov, cert));
                    } catch (CertificateParsingException e) {
                        //Ignore                    
                    }
                }
            } else {
                //if we have no service implementations loaded at all, then we may be in a unit test. Default to X509
                return returnType.cast(new X509CertificateUtility().parseCertificate(provider, cert));
            }
            throw new CertificateParsingException("No certificate could be parsed from byte array. See debug logs for details.");
        }
    }

}
