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

package org.ejbca.core.model.ca.publisher;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.util.Properties;
import java.util.Set;

import com.keyfactor.util.EJBTools;
import com.keyfactor.util.certificate.CertificateWrapper;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.ExternalScriptsAllowlist;

/**
 * This is a class used for testing and example purposes.
 * It is supposed to illustrate how to implement a custom publisher in EJBCA.
 */
public class DummyCustomPublisher implements ICustomPublisher, Serializable {

    /** set this to save the last stored certificate to a file */
    private static final String SAVED_CERTIFICATE_PATH = "savedCertificatePath";

    private static final long serialVersionUID = 1L;

    private static Logger log = Logger.getLogger(DummyCustomPublisher.class);

    private CertificateWrapper certificate = null;

    private String savedCertificatePath;

    /**
     * Creates a new instance of DummyCustomPublisher
     */
    public DummyCustomPublisher() {
    }

    /**
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
     */
    public void init(Properties properties) {
        log.debug("Initializing DummyCustomPublisher " + properties.getProperty(BasePublisher.DESCRIPTION, ""));
        savedCertificatePath = (String) properties.getOrDefault(SAVED_CERTIFICATE_PATH, null);
    }

    /**
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCertificate(org.cesecore.authentication.tokens.AuthenticationToken, java.security.cert.Certificate, java.lang.String, java.lang.String, int, int)
     */
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp,
            int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) throws PublisherException {
        log.debug("DummyCustomPublisher, Storing Certificate for user: " + username);
        this.certificate = EJBTools.wrap(incert);

        if (savedCertificatePath != null) {
            log.debug("DummyCustomPublisher, Saving Certificate to: " + savedCertificatePath);
            try {
                if (this.certificate == null) {
                    Files.deleteIfExists(Path.of(savedCertificatePath));
                } else {
                    try (var file = new FileOutputStream(savedCertificatePath); var objectOutputStream = new ObjectOutputStream(file)) {
                        objectOutputStream.writeObject(this.certificate);
                    }
                }
            } catch (IOException e) {
                log.debug("DummyCustomPublisher, Saving Certificate to: " + savedCertificatePath + " failed:", e);
            }
        }

        return true;
    }

    /**
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCRL(org.cesecore.authentication.tokens.AuthenticationToken, byte[], java.lang.String, int)
     */
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        log.debug("DummyCustomPublisher, Storing CRL");
        return true;
    }

    /**
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#testConnection()
     */
    public void testConnection() throws PublisherConnectionException {
        log.debug("DummyCustomPublisher, Testing connection");
    }

    @Override
    public boolean willPublishCertificate(int status, long revocationDate) {
        return true;
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

    @Override
    public Set<String> getDeclaredPropertyNames() {
        return Set.of(SAVED_CERTIFICATE_PATH);
    }

    /** Save the last published certificate to a file */
    static public void saveCertificateToFile(String path, CertificateWrapper wrappedCertificate) {
        try {
            if (wrappedCertificate == null)
                Files.deleteIfExists(Path.of(path));
            else {
                try (var file = new FileOutputStream(path); var objectOutputStream = new ObjectOutputStream(file)) {
                    objectOutputStream.writeObject(wrappedCertificate);
                }
            }
        } catch (IOException e) {
            // fail silently - this is just for tests
        }
    }

    /** Read the last published certificate to a file 
     * @throws IOException 
     * @throws FileNotFoundException 
     * @throws ClassNotFoundException */
    static public CertificateWrapper readCertificateFromFile(String path) throws FileNotFoundException, IOException, ClassNotFoundException {
        var certificateFile = new File(path);
        if (!certificateFile.exists())
            return EJBTools.wrap((Certificate) null);

        try (var file = new FileInputStream(certificateFile);
             var objectInputStream = new ObjectInputStream(file)) {
            return (CertificateWrapper) objectInputStream.readObject();
        } 
    }
}
