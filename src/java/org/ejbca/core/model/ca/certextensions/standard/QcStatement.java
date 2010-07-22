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

package org.ejbca.core.model.ca.certextensions.standard;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.certextensions.CertificateExtensionException;
import org.ejbca.core.model.ca.certextensions.CertificateExtentionConfigurationException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;

/** QCStatement (rfc3739)
 * 
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.      
 * 
 * @author: Tomas Gustavsson
 * @version $Id$
 */
public class QcStatement extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(QcStatement.class);
	
	/**
	 * Constructor for creating the certificate extension 
	 */
	public QcStatement() {
		super();
	}

	/**
	 * @see StandardCertificateExtension#init(CertificateProfile)
	 */
	public void init(CertificateProfile certProf) {
		super.setOID(X509Extensions.QCStatements.getId());
		super.setCriticalFlag(certProf.getQCStatementCritical());
	}
	/**
	 * Method that should return the DEREncodable value used in the extension
	 * this is the method at all implementors must implement.
	 * 
	 * @param userData the userdata of the issued certificate.
	 * @param ca the CA data with access to all the keys etc
	 * @param certProfile the certificate profile
	 * @return a DEREncodable or null.
	 */
	public DEREncodable getValue(UserDataVO subject, CA ca, CertificateProfile certProfile, PublicKey userPublicKey, PublicKey caPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		DERSequence ret = null;
		String names = certProfile.getQCStatementRAName();
		GeneralNames san = CertTools.getGeneralNamesFromAltName(names);
		SemanticsInformation si = null;
		if (san != null) {
			if (StringUtils.isNotEmpty(certProfile.getQCSemanticsId())) {
				si = new SemanticsInformation(new DERObjectIdentifier(certProfile.getQCSemanticsId()), san.getNames());
			} else {
				si = new SemanticsInformation(san.getNames());                     
			}
		} else if (StringUtils.isNotEmpty(certProfile.getQCSemanticsId())) {
			si = new SemanticsInformation(new DERObjectIdentifier(certProfile.getQCSemanticsId()));                 
		}
		ArrayList qcs = new ArrayList();
		QCStatement qc = null;
		// First the standard rfc3739 QCStatement with an optional SematicsInformation
		DERObjectIdentifier pkixQcSyntax = RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1;
		if (certProfile.getUsePkixQCSyntaxV2()) {
			pkixQcSyntax = RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2;
		}
		if ( (si != null)  ) {
			qc = new QCStatement(pkixQcSyntax, si);
			qcs.add(qc);
		} else {
			qc = new QCStatement(pkixQcSyntax);
			qcs.add(qc);
		}
		// ETSI Statement that the certificate is a Qualified Certificate
		if (certProfile.getUseQCEtsiQCCompliance()) {
			qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance);
			qcs.add(qc);
		}
		// ETSI Statement regarding limit on the value of transactions
		if (certProfile.getUseQCEtsiValueLimit()) {
			// Both value and currency must be available for this extension
			if ( (certProfile.getQCEtsiValueLimit() > 0) && (certProfile.getQCEtsiValueLimitCurrency() != null) ) {
				int limit = certProfile.getQCEtsiValueLimit();
				// The exponent should be default 0
				int exponent = certProfile.getQCEtsiValueLimitExp();
				MonetaryValue value = new MonetaryValue(new Iso4217CurrencyCode(certProfile.getQCEtsiValueLimitCurrency()), limit, exponent);
				qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue, value);
				qcs.add(qc);
			}
		}

		if (certProfile.getUseQCEtsiRetentionPeriod()) {
			DERInteger years = new DERInteger( ((Integer) certProfile.getQCEtsiRetentionPeriod()) );
          		qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_RetentionPeriod, years);
		        qcs.add(qc);
	        }
        
		// ETSI Statement claiming that the private key resides in a Signature Creation Device
		if (certProfile.getUseQCEtsiSignatureDevice()) {
			qc = new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD);
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
		if (certProfile.getUseQCCustomString()) {
			if (!StringUtils.isEmpty(certProfile.getQCCustomStringOid()) && !StringUtils.isEmpty(certProfile.getQCCustomStringText())) {
				DERUTF8String str = new DERUTF8String(certProfile.getQCCustomStringText());
				DERObjectIdentifier oid = new DERObjectIdentifier(certProfile.getQCCustomStringOid());
				qc = new QCStatement(oid, str);
				qcs.add(qc);            		 
			}
		}
		if (qcs.size() >  0) {
			ASN1EncodableVector vec = new ASN1EncodableVector();
			Iterator iter = qcs.iterator();
			while (iter.hasNext()) {
				QCStatement q = (QCStatement)iter.next();
				vec.add(q);
			}
			ret = new DERSequence(vec);
		}
		if (ret == null) {
			log.error("QcStatements is used, but no statement defined!");
		}
		return ret;
	}	
}
