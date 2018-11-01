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
package org.cesecore.certificates.certificate;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;

import org.cesecore.util.CertTools;

/**
 * 
 * Wrapper class for returning cloned specific CertificateData and Base64CertData objects. 
 * 
 * @version $Id$
 *
 */
public class CertificateDataWrapper implements CertificateWrapper, Comparable<CertificateDataWrapper>, Serializable {

    private static final long serialVersionUID = 1L;

    private final BaseCertificateData certificateData;
    private final Base64CertData base64CertData;
    private final byte[] certificateBytes;
    private transient Certificate certificate = null;

    public CertificateDataWrapper(final Certificate certificate, final CertificateData certificateData, final Base64CertData base64CertData) {
        this.certificate = certificate;
        if (certificate==null) {
            this.certificateBytes = null;
        } else {
            try {
                this.certificateBytes = certificate.getEncoded();
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException(e);
            }
        }
        if (certificateData != null) {
            this.certificateData = new CertificateData(certificateData);
        } else {
            this.certificateData = null;
        }
        if (base64CertData != null) {
            this.base64CertData = new Base64CertData(base64CertData);
        } else {
            this.base64CertData = null;
        }
    }

    public CertificateDataWrapper(final CertificateData certificateData, final Base64CertData base64CertData) {
        this.certificate = certificateData.getCertificate(base64CertData);
        if (certificate==null) {
            this.certificateBytes = null;
        } else {
            try {
                this.certificateBytes = certificate.getEncoded();
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException(e);
            }
        }
        this.certificateData = new CertificateData(certificateData);
        if (base64CertData != null) {
            this.base64CertData = new Base64CertData(base64CertData);
        } else {
            this.base64CertData = null;
        }
    }
    
    public CertificateDataWrapper(final NoConflictCertificateData noConflictCertData) {
        this.certificateData = noConflictCertData;
        this.certificateBytes = null;
        this.base64CertData = null;
    }
    
    /**
     * Returns the BaseCertificateData entity object, may be CertificateData or NoConflictCertificateData entity object.
     * 
     * Note that the NoConflictCertificateData table is append only, so no updates to existing objects!
     */
    public BaseCertificateData getBaseCertificateData() {
        return certificateData;
    }

    /**
     * Returns the CertificateData entity object, or throws if the certificate is stored in NoConflictCertificateData
     * @throws ClassCastException If certificate is stored in NoConflictCertificateData
     */
    public CertificateData getCertificateData() {
        return (CertificateData) certificateData;
    }
    
    /**
     * Returns the CertificateData object, or a copy converted to CertificateData, if it was a NoConflictCertificateData entity object.
     * @returns CertificateData object. Do not modify the returned object! Modifications might not be written back to the database.
     */
    public CertificateData getCertificateDataOrCopy() {
        if (certificateData instanceof CertificateData) {
            return (CertificateData) certificateData;
        } else if (certificateData instanceof NoConflictCertificateData) {
            return new CertificateData(certificateData); 
        } else {
            throw new IllegalStateException("Unexpected subclass");
        }
    }

    public Base64CertData getBase64CertData() {
        return base64CertData;
    }

    @Override
    public Certificate getCertificate() {
        if (certificate==null && certificateBytes!=null) {
            // Lazy restore in case of deserialization
            try {
                certificate = CertTools.getCertfromByteArray(certificateBytes, Certificate.class);
            } catch (CertificateParsingException e) {
                throw new IllegalStateException(e);
            }
        }
        return certificate;
    }

    @Override
    public int compareTo(final CertificateDataWrapper other) {
        if (getCertificate()!=null && other.getCertificate()!=null) {
            // Sort descending by issuance date if certificates are available 
            return new Long(CertTools.getNotBefore(other.getCertificate()).getTime()).compareTo(CertTools.getNotBefore(getCertificate()).getTime());          
        } else {
            // Sort descending by expiration date if certificates are not available        
            return new Long(other.getCertificateData().getExpireDate()).compareTo(getCertificateData().getExpireDate());
        }
    }

    @Override
    public boolean equals(final Object other) {
        if (!(other instanceof CertificateDataWrapper)) {
            return false;
        }
        final CertificateDataWrapper otherCertData = (CertificateDataWrapper) other;
        return certificateData.equals(otherCertData.getCertificateData());
    }

    @Override
    public int hashCode() {
        return certificateData.hashCode();
    }

}
