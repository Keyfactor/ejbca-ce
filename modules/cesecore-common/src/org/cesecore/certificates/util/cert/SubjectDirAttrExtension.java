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
package org.cesecore.certificates.util.cert;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;

import com.keyfactor.util.CertTools;

/**
 * A class for reading values from SubjectDirectoryAttributes extension.
 *
 * @version $Id$
 */
public class SubjectDirAttrExtension extends CertTools {

    private static final Logger log = Logger.getLogger(SubjectDirAttrExtension.class);
    
    /**
     * inhibits creation of new SubjectDirAttrExtension
     */
    private SubjectDirAttrExtension() {
    }

    /**
	 * SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
	 *
	 * Attribute ::= SEQUENCE {
     *  type AttributeType,
     *  values SET OF AttributeValue }
     *  -- at least one value is required
     * 
     * AttributeType ::= OBJECT IDENTIFIER
     * AttributeValue ::= ANY
     * 
	 * SubjectDirectoryAttributes is of form 
	 * dateOfBirth=<19590927>, placeOfBirth=<string>, gender=<M/F>, countryOfCitizenship=<two letter ISO3166>, countryOfResidence=<two letter ISO3166>
     * 
     * Supported subjectDirectoryAttributes are the ones above 
	 *
	 * @param certificate containing subject directory attributes
	 * @return String containing directoryAttributes of form the form specified above or null if no directoryAttributes exist. 
	 *   Values in returned String is from CertTools constants. 
	 *   DirectoryAttributes not supported are simply not shown in the resulting string.  
     *  
	 * @throws java.text.ParseException when id_pda_dateOfBirth is malformed
     * @throws IllegalArgumentException if the ASN.1 in the subjectDirectoryAttributes is malformed
	 */
	public static String getSubjectDirectoryAttributes(Certificate certificate) throws ParseException {
		log.debug("Search for SubjectDirectoryAttributes");
		String result = null;
		if (certificate instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) certificate;
			ASN1Primitive obj = CertTools.getExtensionValue(x509cert, Extension.subjectDirectoryAttributes.getId());
			result = getSubjectDirectoryAttribute(obj);
		}
		return result;
	}

	/** Parses Extension value with SubjectDirectoryAttributes.
	 * 
	 * final Extension subjectDirectoryAttributes = CertTools.getExtension(pkcs10CertificateRequest, Extension.subjectDirectoryAttributes.getId());
     * if (subjectDirectoryAttributes != null) {
     *     ASN1Primitive parsedValue = (ASN1Primitive) subjectDirectoryAttributes.getParsedValue();
     *     final String subjectDirectoryAttributeString = SubjectDirAttrExtension.getSubjectDirectoryAttribute(parsedValue);
     * ...
     * 
	 * Supported subjectDirectoryAttributes are the ones in the method above 
	 *
	 * @param obj certificate extension value for subject directory attributes, ASN1Primitive obj = CertTools.getExtensionValue(x509cert, Extension.subjectDirectoryAttributes.getId());
	 * @return String containing directoryAttributes of form the form specified above or null if no directoryAttributes exist. 
	 *   Values in returned String is from CertTools constants. 
	 *   DirectoryAttributes not supported are simply not shown in the resulting string.  
	 *  
	 * @throws java.text.ParseException when id_pda_dateOfBirth is malformed
	 * @throws IllegalArgumentException if the ASN.1 is malformed
	 */
	public static String getSubjectDirectoryAttribute(ASN1Primitive obj) throws ParseException {
		StringBuilder result;
		result = new StringBuilder();
		if (obj == null) {
			return null;
		}
		ASN1Sequence seq = ASN1Sequence.getInstance(obj);

		String prefix = "";
		SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMdd");
		for (int i = 0; i < seq.size(); i++) {
			Attribute attr = Attribute.getInstance(seq.getObjectAt(i));
			if (result.length() != 0) {
				prefix = ", ";
			}
			switch (attr.getAttrType().getId()) {
			case id_pda_dateOfBirth: {
				ASN1Set set = attr.getAttrValues();
				// Come on, we'll only allow one dateOfBirth, we're not allowing such frauds with multiple birth dates
				ASN1GeneralizedTime time = ASN1GeneralizedTime.getInstance(set.getObjectAt(0));
				Date date = time.getDate();
				String dateStr = dateF.format(date);
				result.append(prefix).append("dateOfBirth=").append(dateStr);
				break;
			}
			case id_pda_placeOfBirth: {
				ASN1Set set = attr.getAttrValues();
				// same here only one placeOfBirth
				String pb = ((ASN1String)set.getObjectAt(0)).getString();
				result.append(prefix).append("placeOfBirth=").append(pb);
				break;
			}
			case id_pda_gender: {
				ASN1Set set = attr.getAttrValues();
				// same here only one gender
				String g = ((ASN1String)set.getObjectAt(0)).getString();
				result.append(prefix).append("gender=").append(g);
				break;
			}
			case id_pda_countryOfCitizenship: {
				ASN1Set set = attr.getAttrValues();
				// same here only one citizenship
				String g = ((ASN1String)set.getObjectAt(0)).getString();
				result.append(prefix).append("countryOfCitizenship=").append(g);
				break;
			}
			case id_pda_countryOfResidence: {
				ASN1Set set = attr.getAttrValues();
				// same here only one residence
				String g = ((ASN1String)set.getObjectAt(0)).getString();
				result.append(prefix).append("countryOfResidence=").append(g);
				break;
			}
			default:
				if (log.isDebugEnabled()) {
					log.debug("Unsupported attribute in Subject Directory Attributes: " + attr.getAttrType().getId());
				}
			}
		}
		if (result.length() == 0) {
			return null;
		}
		return result.toString();
	}

	/**
     * From subjectDirAttributes string as defined in getSubjectDirAttribute 
     * @param dirAttr string of SubjectDirectoryAttributes
     * @return A Collection of ASN.1 Attribute (org.bouncycastle.asn1.x509), or an empty Collection, never null
     * @see #getSubjectDirectoryAttributes(Certificate)
     */
    public static Collection<Attribute> getSubjectDirectoryAttributes(String dirAttr) {
        final ArrayList<Attribute> ret = new ArrayList<>();
        ret.addAll(makeAsn1Attributes(id_pda_countryOfResidence, "countryOfResidence", dirAttr));
        ret.addAll(makeAsn1Attributes(id_pda_countryOfCitizenship, "countryOfCitizenship", dirAttr));
        String value = CertTools.getPartFromDN(dirAttr, "gender");
        if (!StringUtils.isEmpty(value)) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(new DERPrintableString(value));
            ret.add(new Attribute(new ASN1ObjectIdentifier(id_pda_gender),new DERSet(vec)));
        }
        value = CertTools.getPartFromDN(dirAttr, "placeOfBirth");
        if (!StringUtils.isEmpty(value)) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            X509DefaultEntryConverter conv = new X509DefaultEntryConverter();
            ASN1Primitive obj = conv.getConvertedValue(new ASN1ObjectIdentifier(id_pda_placeOfBirth), value);
            vec.add(obj);
            ret.add(new Attribute(new ASN1ObjectIdentifier(id_pda_placeOfBirth),new DERSet(vec)));
        }        
        // dateOfBirth that is a GeneralizedTime
        // The correct format for this is YYYYMMDD, it will be padded to YYYYMMDD120000Z
        value = CertTools.getPartFromDN(dirAttr, "dateOfBirth");
        if (!StringUtils.isEmpty(value)) {
            if (value.length() == 8) {
                value += "120000Z"; // standard format according to rfc3739
                ASN1EncodableVector vec = new ASN1EncodableVector();
                vec.add(new DERGeneralizedTime(value));
                ret.add(new Attribute(new ASN1ObjectIdentifier(id_pda_dateOfBirth),new DERSet(vec)));
            } else {
                log.error("Wrong length of data for 'dateOfBirth', should be of format YYYYMMDD, skipping...");
            }
        }
        return ret;
    }

    private static List<Attribute> makeAsn1Attributes(final String attributeOid, final String attributeName, final String dirAttrs) {
        final List<Attribute> ret = new ArrayList<>();
        final List<String> values = CertTools.getPartsFromDN(dirAttrs, attributeName);
        for (final String value : values) {
            if (!StringUtils.isEmpty(value)) {
                ASN1EncodableVector vec = new ASN1EncodableVector();
                vec.add(new DERPrintableString(value));
                ret.add(new Attribute(new ASN1ObjectIdentifier(attributeOid),new DERSet(vec)));
            }
        }
        return ret;
    }
    

}
