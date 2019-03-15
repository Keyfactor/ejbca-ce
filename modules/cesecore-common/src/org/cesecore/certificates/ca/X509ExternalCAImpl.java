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
package org.cesecore.certificates.ca;

import java.security.cert.Certificate;
import java.util.Date;
import java.util.HashMap;

import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * Limited CA implementation containing necessary functionality for CA operations on external instances.
 * @version $Id$
 *
 */
public class X509ExternalCAImpl extends CABaseCommon {

    private static final long serialVersionUID = 1L;
    private static final String CA_TYPE = "X509CA_EXTERNAL";
    
    public X509ExternalCAImpl(final X509CAInfo cainfo) {
        init(cainfo);
    }
    
    public X509ExternalCAImpl(final HashMap<Object, Object> data, final int caId, final String subjectDn, final String name, final int status,
            final Date updateTime, final Date expireTime) {
        init(data);
        setExpireTime(expireTime);
        X509CAInfo info =  new X509CAInfo.X509CAInfoBuilder()
                .setSubjectDn(subjectDn)
                .setName(name)
                .setStatus(status)
                .setUpdateTime(updateTime)
                .setCertificateProfileId(getCertificateProfileId())
                .setExpireTime(getExpireTime())
                .setCaType(getCAType())
                .setSignedBy(getSignedBy())
                .setCertificateChain(getCertificateChain())
                .setCaToken(getCAToken())
                .setDescription(getDescription())
                .setRevocationReason(getRevocationReason())
                .setRevocationDate(getRevocationDate())
                .build();
        super.setCAInfo(info);
        setCAId(caId);
    }
    
    public X509ExternalCAImpl() {
    }
    
    @Override
    public void createOrRemoveLinkCertificate(CryptoToken cryptoToken, boolean createLinkCertificate, CertificateProfile certProfile,
            AvailableCustomCertificateExtensionsConfiguration cceConfig, Certificate oldCaCert) throws CryptoTokenOfflineException {
        // TODO Auto-generated method stub
        
    }

    @Override
    public float getLatestVersion() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public void upgrade() {
        // TODO Auto-generated method stub
        
    }

    @Override
    public String getCaImplType() {
        return CA_TYPE;
    }

}
