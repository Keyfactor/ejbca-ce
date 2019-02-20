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
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

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
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.endentity.PSD2RoleOfPSPStatement;
import org.cesecore.util.CertTools;

/** QCStatement (rfc3739)
 * 
 * Class for standard X509 certificate extension. 
 * This extension have some basics defined in RFC 3739, but the majority of fields are used in EU purposes 
 * and specified in EU standards.
 * ETSI EN 319 412-5 (v2.1.1, 2016-02 or later)
 * https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.01.01_60/en_31941205v020101p.pdf
 * ETSI TS 101 862 (v1.3.3, 2006-01 or later)
 * https://www.etsi.org/deliver/etsi_ts/101800_101899/101862/01.03.03_60/ts_101862v010303p.pdf
 * ETSI TS 119 495 (v1.1.2, 2018-07 or later)
 * https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.01.02_60/ts_119495v010102p.pdf
 * 
 * qcStatements  EXTENSION ::= {
 *        SYNTAX             QCStatements
 *        IDENTIFIED BY      id-pe-qcStatements }
 * id-pe-qcStatements     OBJECT IDENTIFIER ::= { id-pe 3 }
 *
 *    QCStatements ::= SEQUENCE OF QCStatement
 *    QCStatement ::= SEQUENCE {
 *        statementId   QC-STATEMENT.&Id({SupportedStatements}),
 *        statementInfo QC-STATEMENT.&Type
 *        ({SupportedStatements}{@statementId}) OPTIONAL }
 *
 *    SupportedStatements QC-STATEMENT ::= { qcStatement-1,...}
 * 
 * @version $Id$
 */
public class QcStatement extends StandardCertificateExtension {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(QcStatement.class);

    public static final String id_etsi_psd2_qcStatement = "0.4.0.19495.2";
    public static final String id_etsi_psd2_role_psp_as = "0.4.0.19495.1.1";
    public static final String id_etsi_psd2_role_psp_pi = "0.4.0.19495.1.2";
    public static final String id_etsi_psd2_role_psp_ai = "0.4.0.19495.1.3";
    public static final String id_etsi_psd2_role_psp_ic = "0.4.0.19495.1.4";
    
    private static final Map<String, String> psd2RoleIdNameMap = new HashMap<>();
    static {
        psd2RoleIdNameMap.put("PSP_AS", id_etsi_psd2_role_psp_as);
        psd2RoleIdNameMap.put("PSP_PI", id_etsi_psd2_role_psp_pi);
        psd2RoleIdNameMap.put("PSP_AI", id_etsi_psd2_role_psp_ai);
        psd2RoleIdNameMap.put("PSP_IC", id_etsi_psd2_role_psp_ic);
    }
    
    /** @return the ETSI PSD2 role OID of the corresponding given role name */
    public static String getPsd2Oid(final String roleName) {
        return psd2RoleIdNameMap.get(roleName);
    }

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
            qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType, seq);
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
            qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcPds, new DERSequence(locations));
            qcs.add(qc);
        }
        
        // PSD2 QC statement as specified in ETSI TS 119 495
        // All fields for PSD2 are user specific, which is in contrast to the other fields in the QC statement that are issuer specific
        if (certProfile.getUseQCPSD2()) {
            if (subject == null) {
                throw new CertificateExtensionException("A PDS2 QC Extension must contain RolesOfPSP, NCAName and NCAId, which are part of the EndEntityInformation");
            }
            final ExtendedInformation ei = subject.getExtendedInformation();
            if (ei != null) {
                final List<PSD2RoleOfPSPStatement> rolesofpsp = ei.getQCEtsiPSD2RolesOfPSP();
                final String nCAName = ei.getQCEtsiPSD2NCAName();
                final String nCAID = ei.getQCEtsiPSD2NCAId();
                if (rolesofpsp == null || nCAName == null || nCAID == null) {
                    throw new CertificateExtensionException("A PDS2 QC Extension must contain all of RolesOfPSP, NCAName and NCAId");
                }
                // PSD2QcType ::= SEQUENCE{
                //    rolesOfPSP RolesOfPSP,
                //    nCAName NCAName,
                //    nCAId NCAId }
                final ASN1EncodableVector psd2QcType = new ASN1EncodableVector();
                // RolesOfPSP ::= SEQUENCE OF RoleOfPSP
                // RoleOfPSP ::= SEQUENCE {
                //   roleOfPspOid, RoleOfPspOid,
                //   roleOfPspName RoleOfPspName }
                final ASN1EncodableVector psd2RolesOfPsp = new ASN1EncodableVector();
                for (PSD2RoleOfPSPStatement role : rolesofpsp) {
                    if (role.getName().length() > 256) {
                        throw new CertificateExtensionException("A PDS2 RoleOfPspName can max be 256 characters, see ETSI TS 119 495");
                    }
                    final ASN1EncodableVector psd2RoleOfPsp = new ASN1EncodableVector();
                    // RoleOfPspOid ::= OBJECT IDENTIFIER
                    psd2RoleOfPsp.add(new ASN1ObjectIdentifier(role.getOid()));
                    // RoleOfPspName ::= utf8String (SIZE(256))
                    psd2RoleOfPsp.add(new DERUTF8String(role.getName()));
                    psd2RolesOfPsp.add(new DERSequence(psd2RoleOfPsp));
                }
                if (psd2RolesOfPsp.size() == 0) {
                    throw new CertificateExtensionException("There must be at least one RoleOfPspName, see ETSI TS 119 495");
                }
                psd2QcType.add(new DERSequence(psd2RolesOfPsp));
                // NCAName ::= utf8String (SIZE (256))
                if (StringUtils.isEmpty(nCAName) || nCAName.length() > 256) {
                    throw new CertificateExtensionException("A PDS2 NCAName can max be 256 characters, see ETSI TS 119 495");
                }
                psd2QcType.add(new DERUTF8String(nCAName));
                // NCAId ::= utf8String (SIZE (256))
                if (StringUtils.isEmpty(nCAID) || nCAID.length() > 256) {
                    throw new CertificateExtensionException("A PDS2 NCAId can max be 256 characters, see ETSI TS 119 495");
                }
                psd2QcType.add(new DERUTF8String(nCAID));
                // OID from TS 119 495
                qc = new QCStatement(new ASN1ObjectIdentifier(id_etsi_psd2_qcStatement), new DERSequence(psd2QcType));
                qcs.add(qc);
            } else {
                throw new CertificateExtensionException("A PDS2 QC Extension must be included, but no PSD2 subject information is available.");
            }            
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
