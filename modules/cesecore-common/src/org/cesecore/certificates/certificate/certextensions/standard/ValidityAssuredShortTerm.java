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

import com.keyfactor.util.CertTools;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERNull;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

import java.security.PublicKey;

/**
 * This extension indicates that the validity of the certificate is assured because the certificate is a "short-term
 * certificate". That is, the time as indicated in the certificate attribute from notBefore through notAfter, inclusive,
 * is shorter than the maximum time to process a revocation request as specified by the certificate practice statement
 * or certificate policy.
 * <p>
 * The ASN.1 module defined in the present clause shall import the types and structures from IETF RFC 5912 [6] as
 * written in the import part of the module.
 *
 * <pre>
 * ETSIValAssuredCertMod
 *    { itu-t(0) identified-organization(4) etsi(0) id-cert-profile(194121) id-mod(0)
 *  	id-mod-validity-assured(1) v1(0) }
 * BEGIN
 *
 * -- EXPORTS All –
 *
 * IMPORTS
 *
 * EXTENSION
 * FROM PKIX-CommonTypes-2009
 *    { iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5)
 * 			pkix(7)
 *  	id-mod(0) id-mod-pkixCommon-02(57) }
 * -- Extensions
 * id-etsi-ext 		OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0)
 *  										id-cert-profile(194121) 2 }
 *  -- Extension for short-term certificate
 *  id-etsi-ext-valassured-ST-certs 	OBJECT IDENTIFIER ::= { id-etsi-ext 1 }
 *  ext-etsi-valassured-ST-certs EXTENSION ::= { SYNTAX NULL IDENTIFIED BY
 *  										id-etsi-ext-valassured-ST-certs }
 *
 * END
 * </pre>
 */
public class ValidityAssuredShortTerm extends StandardCertificateExtension {

	@Override
	public void init(final CertificateProfile certProf) {
		super.setOID(CertTools.OID_VALIDITY_ASSURED_SHORT_TERM);
		super.setCriticalFlag(certProf.getValidityAssuredShortTermCritical());
	}

	@Override
	public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
								  final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) {
		return DERNull.INSTANCE;
	}
}
