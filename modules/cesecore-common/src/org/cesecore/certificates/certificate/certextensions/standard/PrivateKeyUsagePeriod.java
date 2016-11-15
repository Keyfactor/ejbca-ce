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
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Class for standard X509 certificate extension. See rfc3280 or later for spec of this extension.
 * 
 * @version $Id$
 */
public class PrivateKeyUsagePeriod extends StandardCertificateExtension {

    private static final long serialVersionUID = 1L;
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(PrivateKeyUsagePeriod.class);

    @Override
    public void init(CertificateProfile certProf) {
        super.setOID(Extension.privateKeyUsagePeriod.getId());
        super.setCriticalFlag(false);
    }

    @Override
    public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) throws 
            CertificateExtensionException {
        // Construct the start and end dates of PrivateKeyUsagePeriod
        // As start date, use the same as the start date of the certificate
        long start;
        if (val != null) {
            start = val.getNotBefore().getTime();
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No validity passed in to getValue, using default 'Date().getTime() - CertificateValidity.getValidityOffset()'");
            }
            start = new Date().getTime() - CertificateValidity.getValidityOffset();
        }
        if (certProfile.isUsePrivateKeyUsagePeriodNotBefore()) {
            start += certProfile.getPrivateKeyUsagePeriodStartOffset() * 1000;
        }
        Date notBefore = null;
        Date notAfter = null;

        if (certProfile.isUsePrivateKeyUsagePeriodNotBefore()) {
            notBefore = new Date(start);
        }
        if (certProfile.isUsePrivateKeyUsagePeriodNotAfter()) {
            final long validity = certProfile.getPrivateKeyUsagePeriodLength(); // seconds
            notAfter = new Date(start + validity * 1000);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("PrivateKeyUsagePeriod.notBefore: " + notBefore);
            LOG.debug("PrivateKeyUsagePeriod.notAfter: " + notAfter);
        }

        return privateKeyUsagePeriod(notBefore, notAfter);
    }

    private static DERSequence privateKeyUsagePeriod(final Date notBefore, final Date notAfter) throws CertificateExtensionException {
        // Create the extension.
        // PrivateKeyUsagePeriod ::= SEQUENCE {
        // notBefore [0] GeneralizedTime OPTIONAL,
        // notAfter [1] GeneralizedTime OPTIONAL }
        final ASN1EncodableVector v = new ASN1EncodableVector();
        if (notBefore != null) {
            v.add(new DERTaggedObject(false, 0, new DERGeneralizedTime(notBefore)));
        }
        if (notAfter != null) {
            v.add(new DERTaggedObject(false, 1, new DERGeneralizedTime(notAfter)));
        }
        if (v.size() == 0) {
            throw new CertificateExtensionException("At least one of notBefore and notAfter must be specified!");
        }
        return new DERSequence(v);
    }
}
