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
package org.ejbca.mock.publisher;

import java.security.cert.Certificate;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.ExternalScriptsAllowlist;
import org.ejbca.core.model.ca.publisher.FullEntityPublisher;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;

/**
 */
public class MockedThrowAwayRevocationPublisher implements ICustomPublisher, FullEntityPublisher {

    private static final Logger log = Logger.getLogger(MockedThrowAwayRevocationPublisher.class);
    
    private static int lastTestRevocationReason; // Totally non-threadsafe, but fine since this is test code
    
    public static int getLastTestRevocationReason() {
        return lastTestRevocationReason;
    }
    
    /** Called by test EJB to set to a dummy value */
    public static void setLastTestRevocationReason(int revocationReason) {
        lastTestRevocationReason = revocationReason;
    }

    @Override
    public boolean willPublishCertificate(int status, long revocationDate) {
        return true;
    }

    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp,
            int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) throws PublisherException {
        log.debug("storeCertificate called (old variant)");
        lastTestRevocationReason = revocationReason;
        if (log.isDebugEnabled()) {
            log.debug("Revocation reason: " + revocationReason);
        }
        return true;
    }
    
    @Override
    public boolean storeCertificate(final AuthenticationToken authenticationToken, final CertificateData certificateData, final Base64CertData base64CertData) throws PublisherException {
        log.debug("storeCertificate called (new variant)");
        checkNotNull("authenticationToken", authenticationToken);
        checkNotNull("certificateData", certificateData);
        checkNotNull("certificateData.getSubjectDN", certificateData.getSubjectDN());
        lastTestRevocationReason = certificateData.getRevocationReason();
        if (log.isDebugEnabled()) {
            log.debug("Revocation reason: " + certificateData.getRevocationReason());
        }
        return true;
    }

    private void checkNotNull(final String name, final Object obj) {
        if (obj == null) {
            throw new IllegalArgumentException(name + " may not be null");
        }
    }

    @Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        log.debug("storeCRL called. Does nothing");
        return false;
    }

    @Override
    public void testConnection() throws PublisherConnectionException {
        log.debug("testConnection called. Does nothing");
    }

    @Override
    public boolean isFullEntityPublishingSupported() {
        return true;
    }

    @Override
    public void init(Properties properties) {
        // Does nothing
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean storeOcspResponseData(OcspResponseData ocspResponseData) throws PublisherException {
        // Method not applicable for this publisher type!
        return false;
    }

    @Override
    public boolean isCallingExternalScript() {
        return false;        
    }
    
    @Override
    public void setExternalScriptsAllowlist(ExternalScriptsAllowlist allowList) {
        // Method not applicable for this publisher type!        
    }

}
