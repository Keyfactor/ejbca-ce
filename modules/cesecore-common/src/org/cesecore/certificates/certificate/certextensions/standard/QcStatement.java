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
import java.util.ArrayList;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.PKIDisclosureStatement;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;

/** QCStatement (rfc3739)
 * 
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.      
 * 
 * @version $Id$
 */
public class QcStatement extends StandardCertificateExtension {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(QcStatement.class);
	
    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(Extension.qCStatements.getId());
		super.setCriticalFlag(certProf.getQCStatementCritical());
	}
    
    @Override
    public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException {
		DERSequence ret = null;
		final String names = certProfile.getQCStatementRAName();
		final GeneralNames san = CertTools.getGeneralNamesFromAltName(names);
		SemanticsInformation si = null;
		if (san != null) {
			if (StringUtils.isNotEmpty(certProfile.getQCSemanticsId())) {
				si = new SemanticsInformation(new ASN1ObjectIdentifier(certProfile.getQCSemanticsId()), san.getNames());
			} else {
				si = new SemanticsInformation(san.getNames());                     
			}
		} else if (StringUtils.isNotEmpty(certProfile.getQCSemanticsId())) {
			si = new SemanticsInformation(new ASN1ObjectIdentifier(certProfile.getQCSemanticsId()));                 
		}
		final ArrayList<QCStatement> qcs = new ArrayList<QCStatement>();
		QCStatement qc = null;
		// First the standard rfc3739 QCStatement with an optional SematicsInformation
		// We never add RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1. This is so old so we think it has never been used in the wild basically.
		// That means no need to have code we have to maintain for that.
		if (certProfile.getUsePkixQCSyntaxV2()) {
		    ASN1ObjectIdentifier pkixQcSyntax = RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2;
	        if ( (si != null)  ) {
	            qc = new QCStatement(pkixQcSyntax, si);
	            qcs.add(qc);
	        } else {
	            qc = new QCStatement(pkixQcSyntax);
	            qcs.add(qc);
	        }
		}
		// ETSI Statement that the certificate is a Qualified Certificate
		if (certProfile.getUseQCEtsiQCCompliance()) {
			qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance);
			qcs.add(qc);
		}
		// ETSI Statement regarding limit on the value of transactions
		// Both value and currency must be available for this extension
		if (certProfile.getUseQCEtsiValueLimit() &&
				(certProfile.getQCEtsiValueLimit() >= 0) && (certProfile.getQCEtsiValueLimitCurrency() != null) ) {
			final int limit = certProfile.getQCEtsiValueLimit();
			// The exponent should be default 0
			final int exponent = certProfile.getQCEtsiValueLimitExp();
			final MonetaryValue value = new MonetaryValue(new Iso4217CurrencyCode(certProfile.getQCEtsiValueLimitCurrency()), limit, exponent);
			qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue, value);
			qcs.add(qc);
		}

		if (certProfile.getUseQCEtsiRetentionPeriod()) {
			final ASN1Integer years = new ASN1Integer( ((Integer) certProfile.getQCEtsiRetentionPeriod()) );
			qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_RetentionPeriod, years);
			qcs.add(qc);
		}
        
		// ETSI Statement claiming that the private key resides in a Signature Creation Device
		if (certProfile.getUseQCEtsiSignatureDevice()) {
			qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD);
			qcs.add(qc);
		}
		// ETSI QC Type and PDS is new fields in EN 319 412-05 (2016)
		if  (StringUtils.isNotEmpty(certProfile.getQCEtsiType())) {
            final ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(new ASN1ObjectIdentifier(certProfile.getQCEtsiType()));
            ASN1Sequence seq = new DERSequence(vec);
            qc = new QCStatement(new ASN1ObjectIdentifier("0.4.0.1862.1.6"), seq); // ETSIQCObjectIdentifiers.id_etsi_qcs_QcType in BC > 1.54
            qcs.add(qc);
        }
        if (certProfile.getQCEtsiPds() != null) {
            final ASN1EncodableVector locations = new ASN1EncodableVector();
            for (PKIDisclosureStatement pds : certProfile.getQCEtsiPds()) {
                final ASN1EncodableVector location = new ASN1EncodableVector();
                location.add(new DERIA5String(pds.getUrl()));
                location.add(new DERPrintableString(pds.getLanguage()));
                locations.add(new DERSequence(location));
            }
            qc = new QCStatement(new ASN1ObjectIdentifier("0.4.0.1862.1.5"), new DERSequence(locations)); // ETSIQCObjectIdentifiers.id_etsi_qcs_QcPds in BC > 1.54
            qcs.add(qc);
        }
		// Custom UTF8String QC-statement:
		// qcStatement-YourCustom QC-STATEMENT ::= { SYNTAX YourCustomUTF8String
		//   IDENTIFIED BY youroid }
		//   -- This statement gives you the possibility to define your own QC-statement
		//   -- using an OID and a simple UTF8String, with describing text. A sample text could for example be:
		//   -- This certificate, according to Act. No. xxxx Electronic Signature Law is a qualified electronic certificate
		//
		// YourCustomUTF8String ::= UTF8String
		if (certProfile.getUseQCCustomString() && 
				!StringUtils.isEmpty(certProfile.getQCCustomStringOid()) && !StringUtils.isEmpty(certProfile.getQCCustomStringText())) {
			final DERUTF8String str = new DERUTF8String(certProfile.getQCCustomStringText());
			final ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(certProfile.getQCCustomStringOid());
			qc = new QCStatement(oid, str);
			qcs.add(qc);            		 
		}
		if (!qcs.isEmpty()) {
			final ASN1EncodableVector vec = new ASN1EncodableVector();
			final Iterator<QCStatement> iter = qcs.iterator();
			while (iter.hasNext()) {
				final QCStatement q = (QCStatement)iter.next();
				vec.add(q);
			}
			ret = new DERSequence(vec);
		}
		if (ret == null) {
		    log.error("Qualified certificate statements extension has been enabled, but no statements were included!");
		    throw new CertificateExtensionException("If qualified certificate statements extension has been enabled, at least one statement must be included!");
		}
		return ret;
    }	
}
