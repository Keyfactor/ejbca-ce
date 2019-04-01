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

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.util.dn.DNFieldsUtil;
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
    
    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    public X509ExternalCAImpl(final X509CAInfo cainfo) {
        init(cainfo);
        //Verify integrity if caInfo, either one SubjectDN or SubjectAltName needs to be filled in
        if(StringUtils.isEmpty(DNFieldsUtil.removeAllEmpties(cainfo.getSubjectDN())) && StringUtils.isEmpty(cainfo.getSubjectAltName())) {
            throw new IllegalArgumentException("Subject DN and Alt Name can't both be blank for an X509 CA.");
        }
        data.put(SUBJECTALTNAME, cainfo.getSubjectAltName());
        data.put(CABase.CATYPE, CAInfo.CATYPE_X509);
        data.put(VERSION, LATEST_VERSION);
    }
    
    /**
     * Constructor used when retrieving existing X509CA from database.
     */
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
        info.setExternalCdp(getExternalCdp());
        info.setNameChanged(getNameChanged());
    }
    
    public X509ExternalCAImpl() {
    }
    
    @Override
    public void updateCA(CryptoToken cryptoToken, CAInfo cainfo, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws InvalidAlgorithmException {
        super.updateCA(cryptoToken, cainfo, cceConfig);
        X509CAInfo info = (X509CAInfo) cainfo;
        setExternalCdp(info.getExternalCdp());
        setSubjectAltName(info.getSubjectAltName());
    }
    
    @Override
    public void createOrRemoveLinkCertificate(CryptoToken cryptoToken, boolean createLinkCertificate, CertificateProfile certProfile,
            AvailableCustomCertificateExtensionsConfiguration cceConfig, Certificate oldCaCert) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Operation not supported for external X509CA");
        
    }

    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public void upgrade() {
        super.upgrade();
        if (data.get(NAMECHANGED) == null) {
            setNameChanged(false);
        }
    }

    @Override
    public String getCaImplType() {
        return CA_TYPE;
    }

}
