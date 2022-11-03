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
package org.cesecore.certificates.certificate.ssh;

import java.lang.reflect.InvocationTargetException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

public enum SshCertificateFactory {
    INSTANCE;
    
    /**
     * Sorts potential instances by their SSH prefixes, e.g. ecdsa-sha2-nistp384-cert-v01@openssh.com
     */
    private final Map<String, Class<? extends SshCertificate>> sshCertificateImplementations = new HashMap<>();
    
    SshCertificateFactory() {
        for (SshCertificate sshCertificate : ServiceLoader.load(SshCertificate.class)) {
            for (String prefix : sshCertificate.getCertificateImplementations()) {
                sshCertificateImplementations.put(prefix, sshCertificate.getClass());
            }
        }
    }
    
    public SshCertificate getSshCertificate(byte[] sshCertificate) {
        String certificateBody = new String(sshCertificate);
        certificateBody = certificateBody.trim();
        int sshCertificatePrefixEndIndex = certificateBody.indexOf(" ");
        if (sshCertificatePrefixEndIndex < 0) {
            throw new IllegalStateException("SSH certificate prefix is malformed.");
        }
        String certificatePrefix = certificateBody.substring(0, sshCertificatePrefixEndIndex);
        
        if(!sshCertificateImplementations.containsKey(certificatePrefix)) {
            throw new IllegalStateException("SSH certificate implementations not found for: " + certificatePrefix);
        }
        
        try {
            SshCertificate result = sshCertificateImplementations.get(certificatePrefix).getConstructor().newInstance();
            result.init(sshCertificate);
            return result;
        } catch(CertificateEncodingException| SshKeyException | InstantiationException | 
                IllegalAccessException | IllegalArgumentException | InvocationTargetException | 
                NoSuchMethodException | SecurityException e) {
            throw new IllegalStateException("Could not instance class of type " + 
                sshCertificateImplementations.get(certificatePrefix).getCanonicalName(), e);
        }
    }

}
