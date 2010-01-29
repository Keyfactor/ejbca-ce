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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.certextensions.CertificateExtensionException;
import org.ejbca.core.model.ca.certextensions.CertificateExtentionConfigurationException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;

/** 
 * 
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.      
 * 
 * @author: Tomas Gustavsson
 * @version $Id$
 */
public class AuthorityKeyIdentifier extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(AuthorityInformationAccess.class);

	/**
	 * Constructor for creating the certificate extension 
	 */
	public AuthorityKeyIdentifier() {
		super();
	}

	/**
	 * @see StandardCertificateExtension#init(CertificateProfile)
	 */
	public void init(CertificateProfile certProf) {
		super.setOID(X509Extensions.AuthorityKeyIdentifier.getId());
		super.setCriticalFlag(certProf.getAuthorityKeyIdentifierCritical());
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
		org.bouncycastle.asn1.x509.AuthorityKeyIdentifier ret = null;
		// Default value is that we calculate it from scratch!
		// (If this is a root CA we must calculate the AuthorityKeyIdentifier from scratch)
		// (If the CA signing this cert does not have a SubjectKeyIdentifier we must calculate the AuthorityKeyIdentifier from scratch)
		try{
			byte[] keybytes = caPublicKey.getEncoded();
			SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(keybytes)).readObject());
			ret = new org.bouncycastle.asn1.x509.AuthorityKeyIdentifier(apki);

		// If we have a CA-certificate (i.e. this is not a Root CA), we must take the authority key identifier from 
		// the CA-certificates SubjectKeyIdentifier if it exists. If we don't do that we will get the wrong identifier if the 
		// CA does not follow RFC3280 (guess if MS-CA follows RFC3280?)
		X509Certificate cacert = (X509Certificate)ca.getCACertificate();
		boolean isRootCA = (certProfile.getType() == CertificateProfile.TYPE_ROOTCA);
		if ( (cacert != null) && (!isRootCA) ) {
			byte[] akibytes;
			akibytes = CertTools.getSubjectKeyId(cacert);
			if (akibytes != null) {
				// TODO: The code below is snipped from AuthorityKeyIdentifier.java in BC 1.36, because there is no method there
				// to set only a pre-computed key identifier
				// This should be replaced when such a method is added to BC
				ASN1OctetString keyidentifier = new DEROctetString(akibytes);
				ASN1EncodableVector  v = new ASN1EncodableVector();
				v.add(new DERTaggedObject(false, 0, keyidentifier));
				ASN1Sequence seq = new DERSequence(v);
				ret = new org.bouncycastle.asn1.x509.AuthorityKeyIdentifier(seq);
				log.debug("Using AuthorityKeyIdentifier from CA-certificates SubjectKeyIdentifier.");
			}
		}
		} catch (IOException e) {
			CertificateExtensionException ex = new CertificateExtensionException("IOException parsing CA public key: "+e.getMessage(), e);
			throw ex;
		}
		if (ret == null) {
			log.error("AuthorityKeyIdentifier is used, but no key identifier can be created!");
		}
		return ret;
	}	
}
