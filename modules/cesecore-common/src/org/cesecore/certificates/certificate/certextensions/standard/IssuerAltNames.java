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
package org.cesecore.certificates.certificate.certextensions.standard;

import java.security.PublicKey;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;

/**
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.
 * 
 * @version $Id$
 */
public class IssuerAltNames extends StandardCertificateExtension {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(IssuerAltNames.class);

    @Override
    public void init(final CertificateProfile certProf) {
        super.setOID(Extension.issuerAlternativeName.getId());
        super.setCriticalFlag(certProf.getIssuerAlternativeNameCritical());
    }
    
    @Override
    public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) {
        GeneralNames ret = null;
        String altName = null;
        if (ca.getCACertificate() != null) {
            altName = CertTools.getSubjectAlternativeName(ca.getCACertificate());
        } else {
            // If we have a new Root CA (not renewing), we go here
            if (certProfile.getType() == CertificateConstants.CERTTYPE_ROOTCA && ca.getCAInfo() instanceof X509CAInfo) {
                altName = ((X509CAInfo)ca.getCAInfo()).getSubjectAltName();
                if (StringUtils.isNotEmpty(altName) && certProfile.getUseSubjectAltNameSubSet()) {
                    altName = certProfile.createSubjectAltNameSubSet(altName);
                }
                if (log.isDebugEnabled()) {
                    log.debug("Using the SAN value as the IssuerAltName value for Root CA. SAN='" + altName + "'");
                }
            } else if (log.isDebugEnabled()) {
                // This should never happen
                log.debug("Missing CA certificate in CA " + ca.getCAId() + ", and subject is not an X509 Root CA. Will not add IssuerAltName extension");
            }
        }
        if (StringUtils.isNotEmpty(altName)) {
            ret = CertTools.getGeneralNamesFromAltName(altName);
        }
        if (ret == null) {
            if (log.isDebugEnabled()) {
                log.debug("No altnames (SubjectAltName in issuing CA certificate) trying to make IssuerAltName extension: "+altName);
            }
        }
        return ret;
    }   
}
