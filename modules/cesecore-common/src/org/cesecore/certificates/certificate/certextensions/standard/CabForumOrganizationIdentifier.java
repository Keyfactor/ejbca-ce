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
package org.cesecore.certificates.certificate.certextensions.standard;

import java.security.PublicKey;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;

/**
 * Represents the CA/B Forum Organization Identifier, including additional information about
 * an organization to comply with EU regulations. Introduced in <a href="https://cabforum.org/pipermail/servercert-wg/2019-March/000691.html">
 * Ballot SC17 version 2: Alternative registration numbers for EU certificates.</a>
 * 
 * @version $Id$
 */
public class CabForumOrganizationIdentifier extends StandardCertificateExtension {

    private static final long serialVersionUID = 1L;
    
    public static final String OID = "2.23.140.3.1";
    public static final String VALIDATION_REGEX = "[A-Z0-9]{5,5}(\\+[A-Z0-9]+)?-.*";

    @Override
    public void init(final CertificateProfile certProf) {
        super.setOID(OID);
        super.setCriticalFlag(false);
    }

    @Override
    public ASN1Encodable getValue(final EndEntityInformation userData, final CA ca, final CertificateProfile certProfile, final PublicKey userPublicKey,
            final PublicKey caPublicKey, final CertificateValidity val) throws CertificateExtensionException {
        final ExtendedInformation extInfo = userData.getExtendedInformation();
        if (extInfo == null) {
            throw new CertificateExtensionException("End Entity must have \"extended information\" structure.");
        }
        if (StringUtils.isBlank(extInfo.getCabfOrganizationIdentifier())) {
            throw new CertificateExtensionException("CA/B Forum Organization Identifier is blank or missing");
        }
        final ASN1EncodableVector vec = new ASN1EncodableVector();
        try {
            vec.add(new DERPrintableString(extInfo.getCabfRegistrationSchemeIdentifier()));
            vec.add(new DERPrintableString(extInfo.getCabfRegistrationCountry()));
            if (!StringUtils.isBlank(extInfo.getCabfRegistrationStateOrProvince())) {
                vec.add(new DERTaggedObject(false, 0, new DERPrintableString(extInfo.getCabfRegistrationStateOrProvince())));
            }
            vec.add(new DERUTF8String(extInfo.getCabfRegistrationReference()));
        } catch (IndexOutOfBoundsException | IllegalStateException e) {
            throw new CertificateExtensionException("CA/B Forum Organization Identifier is malformed", e);
        }
        return new DERSequence(vec);
    }
    
}
