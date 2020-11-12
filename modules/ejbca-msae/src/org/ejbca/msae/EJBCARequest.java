/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.msae;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.protocol.ws.client.gen.ExtendedInformationWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;

import javax.naming.NamingException;
import java.util.ArrayList;
import java.util.List;

class EJBCARequest {
	private static final Logger log = Logger.getLogger(EJBCARequest.class);
	private UserDataVOWS userDataVOWS;
	private String pkcs10Request;

	EJBCARequest(ApplicationProperties msEnrollmentProperties, TemplateSettings templateSettings, ADObject adObject, String username, String msTemplateHexValue, String pkcs10request) throws EnrollmentException, NamingException {
		buildUserDataVOWS(msEnrollmentProperties, templateSettings, adObject, username, msTemplateHexValue);
		this.pkcs10Request = pkcs10request;
	}

	private void buildUserDataVOWS(ApplicationProperties msEnrollmentProperties, TemplateSettings ts, ADObject adObject, String username, String msTemplateHexValue) throws EnrollmentException, NamingException {

		final String requestSubjectDN = buildSubjectDNForUserDataVOWS(ts, adObject, username);
		final String requestAltNames = buildSubjectAltNameForUserDataVOWS(ts, adObject);
		final String endEntityProfileName = ts.getEeprofile();
		final String certificateProfileName = ts.getCertprofile();
		final String oid = ts.getOid();

		// Nothing more can be done if no certificate profile corresponding to
		// the certificate template in the request was found.
		if (null == certificateProfileName) {
			throw new EnrollmentException("*** No certificate profile corresponding to " + oid + " was found. ***");
		}
		log.info("Certificate Profile: " + certificateProfileName);

		if (null == endEntityProfileName) {
			throw new EnrollmentException("*** No end entity profile corresponding to " + oid + " was found. ***");
		}
		log.info("End Entity Profile: " + endEntityProfileName);

		UserDataVOWS user1 = new UserDataVOWS();

		user1.setUsername(username.toLowerCase());

		if (log.isDebugEnabled()) {
			log.debug("Subject Name to use for certificate request: " + requestSubjectDN);
		}

		user1.setSubjectDN(requestSubjectDN);

		if (log.isDebugEnabled()) {
			log.debug("Subject Alternative Name to use for certificate request: " + requestAltNames);
		}

		if ((null != requestAltNames) && (0 < requestAltNames.length())) {
			user1.setSubjectAltName(requestAltNames);
		}

		user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
		user1.setCertificateProfileName(certificateProfileName);
		user1.setEndEntityProfileName(endEntityProfileName);
		user1.setStatus(UserDataVOWS.STATUS_NEW);

		// The CA Name is user-configurable.
		user1.setCaName(msEnrollmentProperties.getCANAME());

		// Set Custom Extensions for Certificate Template Information
		if (null != msTemplateHexValue) {
			final String msCertificateTemplateInformationOID = "1.3.6.1.4.1.311.21.7";
			List<ExtendedInformationWS> ei = new ArrayList<>();
			ei.add(new ExtendedInformationWS(
					ExtendedInformation.EXTENSIONDATA + msCertificateTemplateInformationOID + ".value",
					msTemplateHexValue));
			user1.setExtendedInformation(ei);
		}

		userDataVOWS = user1;
	}

	private String buildSubjectDNForUserDataVOWS(TemplateSettings templateSettings, ADObject adObject, String username) throws EnrollmentException {
		if (log.isDebugEnabled()) {
			log.debug("*** Building SubjectDN using format: " + templateSettings.getSubject_name_format());
			if (!templateSettings.getAdditional_subjectdn_attributes().equals("")) {
				log.debug(
						"*** Appending " + templateSettings.getAdditional_subjectdn_attributes() + " to the subject.");
			}
		}

		List<String> subjectDNParts = new ArrayList<>();

		final String subject_name_format = templateSettings.getSubject_name_format();
		final boolean include_email_in_subjectdn = templateSettings.isInclude_email_in_subjectdn();
		final String additional_subjectdn_attributes = templateSettings.getAdditional_subjectdn_attributes();

		final String cn = adObject.getCn();
		final String dNSHostName = adObject.getDnsHostName();
		final String distinguishedName = adObject.getDistinguishedName();
		final String userPrincipalName = adObject.getUserPrincipalName();

		// Build SubjectDN
		if (subject_name_format != null) {
			switch (subject_name_format) {
				case "common_name":
					if (cn != null) {
						subjectDNParts.add("CN=" + cn);
					} else {
						throw new EnrollmentException("Error: no CN found for the user");
					}
					break;
				case "dns_name":
					if (dNSHostName != null) {
						subjectDNParts.add("CN=" + dNSHostName);
					} else {
						throw new EnrollmentException("Error: no dNSHostName found for the user");
					}
					break;
				case "fully_distinguished_name":
					if (distinguishedName != null) {
						subjectDNParts.add(distinguishedName);
					} else {
						throw new EnrollmentException("Error: no distinguishedName found for the user");
					}
					break;
				case "upn":
					if (userPrincipalName != null) {
						subjectDNParts.add("CN=" + userPrincipalName);
					} else {
						throw new EnrollmentException("Error: no userPrincipalName found for the user");
					}
					break;
				case "username_with_domain":
					if(username != null) {
						subjectDNParts.add("CN=" + username);
					} else {
						throw new EnrollmentException("Error: could not get username with domain for the user");
					}
					break;
				default:
					throw new EnrollmentException("Error: unknown subject_name_format value.");
			}
		} else {
			throw new EnrollmentException("Error: subject_name_format was not set correctly.");
		}

		// Check if email needs to be included to the SubjectDN
		if (include_email_in_subjectdn) {
			final String mail = adObject.getMail();
			if (mail != null) {
				subjectDNParts.add("E=" + mail);
			} else {
				throw new EnrollmentException("Error: no email found for the user");
			}
		}

		// Append additional subject dn attributes if specified
		if (additional_subjectdn_attributes != null && !additional_subjectdn_attributes.trim().equals("")) {
			subjectDNParts.add(additional_subjectdn_attributes);
		}

		String customSubjectDN = String.join(",", subjectDNParts);

		if (log.isDebugEnabled()) {
			log.debug("SubjectDN: " + customSubjectDN);
		}

		return customSubjectDN;
	}

	private String buildSubjectAltNameForUserDataVOWS(TemplateSettings templateSettings, ADObject adObject)
			throws NamingException, EnrollmentException {
		if (log.isDebugEnabled()) {
			log.debug("*** Building SubjectAltName. ***");
		}

		List<String> subjectAltNameParts = new ArrayList<>();
		final boolean include_email_in_san = templateSettings.isInclude_email_in_san();
		final boolean include_dns_name_in_san = templateSettings.isInclude_dns_name_in_san();
		final boolean include_upn_in_san = templateSettings.isInclude_upn_in_san();
		final boolean include_spn_in_san = templateSettings.isInclude_spn_in_san();
		final boolean include_netbios_in_san = templateSettings.isInclude_netbios_in_san();
		final boolean include_domain_in_san = templateSettings.isInclude_domain_in_san();
		final boolean include_objectguid_in_san = templateSettings.isInclude_objectguid_in_san();

		// Check if email needs to be included to the Subject Alt Name
		if (include_email_in_san) {
			final String mail = adObject.getMail();
			if (mail != null) {
				subjectAltNameParts.add("rfc822Name=" + mail);
			} else {
				throw new EnrollmentException("Error: no email found for the user");
			}
		}

		// Check if email needs to be included to the Subject Alt Name
		if (include_dns_name_in_san) {
			final String dNSHostName = adObject.getDnsHostName();
			if (dNSHostName != null) {
				subjectAltNameParts.add("dNSName=" + dNSHostName);
			} else {
				throw new EnrollmentException("Error: no dNSHostName found for the user");
			}
		}

		if (include_upn_in_san) {
			final String userPrincipalName = adObject.getUserPrincipalName();
			if (userPrincipalName != null) {
				subjectAltNameParts.add("upn=" + userPrincipalName);
			} else {
				throw new EnrollmentException("Error: no userPrincipalName found for the user");
			}
		}

		if (include_spn_in_san) {
			final String userPrincipalName = adObject.getUserPrincipalName();
			if (userPrincipalName != null) {
				subjectAltNameParts.add("upn=" + userPrincipalName);
			} else {
				final String sAMAccountName = adObject.getsAMAccountName();
				final String dnsRoot = adObject.getDnsRoot();
				if (sAMAccountName != null && dnsRoot != null) {
					subjectAltNameParts.add("upn=" + sAMAccountName + "@" + dnsRoot);
				} else {
					throw new EnrollmentException("Error: no userPrincipalName found for the user");
				}
			}
		}

		// Get domain name from dnsRoot in the forest configuration container
		if (include_domain_in_san) {
			final String dnsRoot = adObject.getDnsRoot();
			if (dnsRoot != null) {
				subjectAltNameParts.add("dnsName=" + dnsRoot);
			} else {
				throw new EnrollmentException("Error: Domain name was not found in the forest configuration.");
			}
		}

		// Get NETBIOS name from the forest configuration container
		if (include_netbios_in_san) {
			final String nETBIOSName = adObject.getnETBIOSName();
			if (nETBIOSName != null) {
				subjectAltNameParts.add("dnsName=" + nETBIOSName);
			} else {
				throw new EnrollmentException("Error: no NETBIOS name found for the domain.");
			}
		}

		// Object GUID is useful for DomainController certificates
		if (include_objectguid_in_san) {
			final byte[] objectGUID = adObject.getObjectGUID();
			if (objectGUID != null) {
				final DEROctetString hexguid = new DEROctetString(objectGUID);
				subjectAltNameParts.add("guid=" + hexguid.toString().replaceAll("^#+", ""));

				if (log.isTraceEnabled()) {
					log.trace("Hex value of Object GUID: " + hexguid);
				}

			} else {
				throw new EnrollmentException("Error: no Object GUID found for the user");
			}
		}

		String customSubjectAltName = String.join(",", subjectAltNameParts);

		if (log.isDebugEnabled()) {
			log.debug("Subject Alt Name: " + customSubjectAltName);
		}

		return customSubjectAltName;
	}

    byte[] certificateRequest(EJBCA ejbca) throws EnrollmentException {
		return ejbca.issuePKCS7Certificate(userDataVOWS, pkcs10Request);
	}
}