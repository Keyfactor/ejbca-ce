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
public class CertificateDataWrapper implements Comparable<CertificateDataWrapper>, Serializable {

    private static final long serialVersionUID = 1L;

    private final CertificateData certificateData;
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

    public CertificateData getCertificateData() {
        return certificateData;
    }

    public Base64CertData getBase64CertData() {
        return base64CertData;
    }

    public Certificate getCertificate() {
        if (certificate==null && certificateBytes!=null) {
            // Lazy restore in case of deserialization
            try {
                certificate = CertTools.getCertfromByteArray(certificateBytes);
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
            return Long.compare(CertTools.getNotBefore(other.getCertificate()).getTime(), CertTools.getNotBefore(getCertificate()).getTime());          
        } else {
            // Sort descending by expiration date if certificates are not available        
            return Long.compare(other.getCertificateData().getExpireDate(), getCertificateData().getExpireDate());
        }     
    }

}
