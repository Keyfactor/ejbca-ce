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
package com.widget;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.CustomCertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * @version $Id$
 *
 */
public class WidgetCustomExtension extends CertificateExtension implements CustomCertificateExtension {

    private static final long serialVersionUID = 1L;


    /**
     * 
     */
    public WidgetCustomExtension() {
    }


    @Override
    public int getId() {
        return 1337;
    }

    @Override
    public String getOID() {
        return "1.2.3.4";
    }

    @Override
    public Map<String, String[]> getAvailableProperties() {
        return new HashMap<String, String[]>();
    }

    @Override
    public String getDisplayName() {
        return "WidgetCorp Test Extension";
    }

    @Override
    public boolean isCriticalFlag() {
        return false;
    }


    @Override
    public boolean isRequiredFlag() {
        return false;
    }

    @Override
    public Properties getProperties() {
        return new Properties();
    }

    @Override
    public byte[] getValueEncoded(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException {
        return null;
    }

    @Override
    public byte[] getValueEncoded(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val, String oid) throws CertificateExtensionException {
        return null;
    }


    @Override
    public ASN1Encodable getValue(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException {
        return null;
    }

}
