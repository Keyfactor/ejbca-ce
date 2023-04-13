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
package org.cesecore.certificates.certificate.cvc;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.AuthorizationRole;
import org.ejbca.cvc.CVCAuthorizationTemplate;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.OIDField;
import org.ejbca.cvc.ReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.CertificateImplementation;

/**
 *
 */
public class CvCertificateUtility implements CertificateImplementation {

    private static final Logger log = Logger.getLogger(CvCertificateUtility.class);

    /**
     * 
     */
    public CvCertificateUtility() {
    }

    @Override
    public String getType() {
        return "CVC";
    }

    @Override
    public Class<?> getImplementationClass() {
        return CardVerifiableCertificate.class;
    }

    @Override
    public String getCertificateSignatureAlgorithm(final Certificate certificate) {
        final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) certificate;
        final CVCPublicKey cvcpk;
        try {
            cvcpk = cvccert.getCVCertificate().getCertificateBody().getPublicKey();
            final OIDField oid = cvcpk.getObjectIdentifier();
            return AlgorithmUtil.getAlgorithmName(oid);
        } catch (NoSuchFieldException e) {
            throw new IllegalStateException("Not a valid CVC certificate", e);
        }
    }

    @Override
    public String getSubjectDn(final Certificate certificate) {
        final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) certificate;
        try {
            ReferenceField rf = cvccert.getCVCertificate().getCertificateBody().getHolderReference();
            if (rf != null) {
                // Construct a "fake" DN which can be used in EJBCA
                // Use only mnemonic and country, since sequence is more of a serialnumber than a DN part
                String dn = "";
                if (rf.getMnemonic() != null) {
                    if (StringUtils.isNotEmpty(dn)) {
                        dn += ", ";
                    }
                    dn += "CN=" + rf.getMnemonic();
                }
                if (rf.getCountry() != null) {
                    if (StringUtils.isNotEmpty(dn)) {
                        dn += ", ";
                    }
                    dn += "C=" + rf.getCountry();
                }
                return CertTools.stringToBCDNString(dn);
            } else {
                return null;
            }
        } catch (NoSuchFieldException e) {
            log.error("NoSuchFieldException: ", e);
            return null;
        }
    }

    @Override
    public String getIssuerDn(final Certificate certificate) {
        final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) certificate;
        try {
            ReferenceField rf = cvccert.getCVCertificate().getCertificateBody().getAuthorityReference();
            if (rf != null) {
                // Construct a "fake" DN which can be used in EJBCA
                // Use only mnemonic and country, since sequence is more of a serialnumber than a DN part
                String dn = "";
                if (rf.getMnemonic() != null) {
                    if (StringUtils.isNotEmpty(dn)) {
                        dn += ", ";
                    }
                    dn += "CN=" + rf.getMnemonic();
                }
                if (rf.getCountry() != null) {
                    if (StringUtils.isNotEmpty(dn)) {
                        dn += ", ";
                    }
                    dn += "C=" + rf.getCountry();
                }
                return CertTools.stringToBCDNString(dn);
            } else {
                return null;
            }
        } catch (NoSuchFieldException e) {
            log.error("NoSuchFieldException: ", e);
            return null;
        }
    }

    @Override
    public BigInteger getSerialNumber(final Certificate certificate) {
        // For CVC certificates the sequence field of the HolderReference is kind of a serial number,
        // but if can be alphanumeric which means it can not be made into a BigInteger
        CardVerifiableCertificate cvccert = (CardVerifiableCertificate) certificate;
        try {
            String sequence = cvccert.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
            return CertTools.getSerialNumberFromString(sequence);
        } catch (NoSuchFieldException e) {
            log.error("getSerialNumber: NoSuchFieldException: ", e);
            return BigInteger.valueOf(0);
        }
    }

    @Override
    public String getSerialNumberAsString(final Certificate certificate) {
        // For CVC certificates the sequence field of the HolderReference is kind of a serial number,
        // but if can be alphanumeric which means it can not be made into a BigInteger
        CardVerifiableCertificate cvccert = (CardVerifiableCertificate) certificate;
        try {
            return cvccert.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
        } catch (NoSuchFieldException e) {
            log.error("getSerialNumber: NoSuchFieldException: ", e);
            return "N/A";
        }
    }

    @Override
    public byte[] getSignature(final Certificate certificate) {
        CardVerifiableCertificate cvccert = (CardVerifiableCertificate) certificate;
        try {
            return cvccert.getCVCertificate().getSignature();
        } catch (NoSuchFieldException e) {
            log.error("NoSuchFieldException: ", e);
            return null;
        }
    }

    @Override
    public Date getNotAfter(final Certificate certificate) {
        final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) certificate;
        try {
            return cvccert.getCVCertificate().getCertificateBody().getValidTo();
        } catch (NoSuchFieldException e) {
            // it is not uncommon that this field is missing in CVC certificate requests (it's not in the EAC standard so)
            if (log.isDebugEnabled()) {
                log.debug("NoSuchFieldException: " + e.getMessage());
            }
            return null;
        }
    }

    @Override
    public Date getNotBefore(final Certificate certificate) {
        CardVerifiableCertificate cvccert = (CardVerifiableCertificate) certificate;
        try {
            return cvccert.getCVCertificate().getCertificateBody().getValidFrom();
        } catch (NoSuchFieldException e) {
            // it is not uncommon that this field is missing in CVC certificate requests (it's not in the EAC standard so)
            log.debug("NoSuchFieldException: " + e.getMessage());
            return null;
        }
    }

    @Override
    public Certificate parseCertificate(String provider, byte[] cert) throws CertificateParsingException {
        // We could not create an X509Certificate, see if it is a CVC certificate instead
        try {
            final CVCertificate parsedObject = CertificateParser.parseCertificate(cert);
            return new CardVerifiableCertificate(parsedObject);
        } catch (ParseException e) {
            throw new CertificateParsingException("ParseException trying to read CVCCertificate.", e);
        } catch (ConstructionException e) {
            throw new CertificateParsingException("ConstructionException trying to read CVCCertificate.", e);
        }
    }

    @Override
    public boolean isCA(final Certificate certificate) {
        CardVerifiableCertificate cvccert = (CardVerifiableCertificate) certificate;
        try {
            CVCAuthorizationTemplate templ = cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate();
            AuthorizationRole role = templ.getAuthorizationField().getAuthRole();
            return role.isCVCA() || role.isDV();
        } catch (NoSuchFieldException e) {
            log.error("NoSuchFieldException: ", e);
            return false;
        }
    }

    @Override
    public void checkValidity(final Certificate certificate, final Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) certificate;
        try {
            final Date start = cvccert.getCVCertificate().getCertificateBody().getValidFrom();
            final Date end = cvccert.getCVCertificate().getCertificateBody().getValidTo();
            if (start.after(date)) {
                String msg = "CV Certificate startDate '" + start + "' is after check date '" + date + "'. Subject: " + getSubjectDn(certificate);
                if (log.isTraceEnabled()) {
                    log.trace(msg);
                }
                throw new CertificateNotYetValidException(msg);
            }
            if (end.before(date)) {
                final String msg = "CV Certificate endDate '" + end + "' is before check date '" + date + "'. Subject: " + getSubjectDn(certificate);
                if (log.isTraceEnabled()) {
                    log.trace(msg);
                }
                throw new CertificateExpiredException(msg);
            }
        } catch (NoSuchFieldException e) {
            log.error("NoSuchFieldException: ", e);
        }

    }

    @Override
    public String dumpCertificateAsString(Certificate certificate) {
        final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) certificate;
        final CVCObject obj = cvccert.getCVCertificate();
        return obj.getAsText("");
    }

}
