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

import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * @version $Id$
 *
 */
public enum SshCertificateFactory {
    INSTANCE;
    
    private Map<String, Class<? extends SshCertificate>> sshCertificateImplementations = new HashMap<>();

    private SshCertificateFactory() {
        for (SshCertificate sshCertificate : ServiceLoader.load(SshCertificate.class)) {
            for(String implementation : sshCertificate.getCertificateImplementations()) {
                sshCertificateImplementations.put(implementation, sshCertificate.getClass());
            }
            
        }
    }

    public SshCertificate getSshCertificate(byte[] encodedCertificate) throws CertificateEncodingException, SshKeyException {
        String certificateAsString = new String(encodedCertificate);  
        String[] splitCertificate = certificateAsString.split(" ");
        String comment = certificateAsString.substring(certificateAsString.indexOf(' ' , 1), certificateAsString.length());
        try {
            SshCertificate result = sshCertificateImplementations.get(splitCertificate[0]).newInstance();
            result.init(splitCertificate[1].getBytes());
            result.setComment(comment);
            return result;
        } catch (InstantiationException | IllegalAccessException e) {
            throw new IllegalStateException(
                    "Could not instance certificate of type " + sshCertificateImplementations.get(splitCertificate[0]).getCanonicalName(), e);
        }
    }
}
