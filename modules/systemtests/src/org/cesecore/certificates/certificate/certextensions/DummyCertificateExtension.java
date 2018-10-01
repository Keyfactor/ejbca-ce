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

package org.cesecore.certificates.certificate.certextensions;

import java.io.IOException;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERIA5String;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.internal.InternalResources;

/**
 * Dummy class used for testing certificate extensions in the UI.
 * 
 * @version $Id$
 *
 */

public class DummyCertificateExtension extends CertificateExtension implements CustomCertificateExtension {

    
    private static final long serialVersionUID = -4023989559674323678L;
    private static final Map<String, String[]> propertiesMap = new HashMap<String, String[]>();
    
    static {
        String[] encodingValues = new String[3];
        for(int i = 0; i < encodingValues.length; i++) {
            encodingValues[i] = "encoding value " + i;
        }
        //encodingValues[3] = "";
        propertiesMap.put("encoding", encodingValues);
        propertiesMap.put("value", new String[]{});
        propertiesMap.put("useencoding", CustomCertificateExtension.BOOLEAN);
    }
    
    {
        setDisplayName("Dummy Certificate Extension");
    }
    
    @Override
    public Map<String, String[]> getAvailableProperties() {
        // TODO Auto-generated method stub
        return propertiesMap;
    }

    @Override
    public ASN1Encodable getValue(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Use getValueEncoded instead");
    }
    
    @Override
    public byte[] getValueEncoded(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException {
        final byte[] result;
        String encoding = StringUtils.trim(getProperties().getProperty("encoding"));
        String value = StringUtils.trim(getProperties().getProperty("value"));
        boolean useEncoding = Boolean.parseBoolean(StringUtils.trim(getProperties().getProperty("useencoding", Boolean.FALSE.toString())));
        
        if(useEncoding) {
            value += " - " + encoding; 
        }
        
        ASN1Encodable toret = new DERIA5String(value, true);
        try {
            result = toret.toASN1Primitive().getEncoded();
        } catch (IOException e) {
            throw new CertificateExtensionException(InternalResources.getInstance().getLocalizedMessage("certext.basic.illegalvalue", value,
                    Integer.valueOf(getId()), getOID()));
        }
        return result;
    }

    @Override
    public byte[] getValueEncoded(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val, String oid) throws CertificateExtensionException {
        throw new UnsupportedOperationException("Use the other getValueEncoded implementation.");
    }
}
