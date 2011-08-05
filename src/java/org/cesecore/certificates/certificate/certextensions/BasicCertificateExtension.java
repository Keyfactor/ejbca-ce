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
package org.cesecore.certificates.certificate.certextensions;

import java.math.BigInteger;
import java.security.PublicKey;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.internal.InternalResources;

/**
 * The default basic certificate extension that has two property.
 * 
 * 'value' : The value returned 'encoding' : How the value is encoded.
 * 
 * Optionally, a new property can be defined:
 * 
 * 'nvalues' : number of values of type 'encoding'
 * 
 * Thus, the extension will be of type 'SEQUENCE OF ENCODING' with a size of nvalues. The members will be: 'value1', 'value2' and so on.
 * 
 * See documentation for more information.
 * 
 * Based on EJBCA version: BasicCertificateExtension.java 10397 2010-11-08 14:18:57Z anatom
 * 
 * @version $Id: BasicCertificateExtension.java 667 2011-04-04 07:57:33Z mikek $
 */
public class BasicCertificateExtension extends CertificateExtension {

    private static final InternalResources intres = InternalResources.getInstance();

    private static String ENCODING_DERBITSTRING = "DERBITSTRING";
    private static String ENCODING_DERINTEGER = "DERINTEGER";
    private static String ENCODING_DEROCTETSTRING = "DEROCTETSTRING";
    private static String ENCODING_DERBOOLEAN = "DERBOOLEAN";
    private static String ENCODING_DERPRINTABLESTRING = "DERPRINTABLESTRING";
    private static String ENCODING_DERUTF8STRING = "DERUTF8STRING";
    private static String ENCODING_DERIA5STRING = "DERIA5STRING";
    private static String ENCODING_DERNULL = "DERNULL";
    private static String ENCODING_DEROBJECT = "DEROBJECT";
    private static String ENCODING_DEROID = "DERBOJECTIDENTIFIER";

    // Defined Properties
    private static String PROPERTY_VALUE = "value";
    private static String PROPERTY_ENCODING = "encoding";
    private static String PROPERTY_NVALUES = "nvalues";

    private DEREncodable dEREncodable = null;

    /**
     * Returns the defined property 'value' in the encoding specified in 'encoding'.
     * 
     * @param userData
     *            not used
     * @param ca
     *            not used
     * @param certProfile
     *            not used
     * @see org.cesecore.certificates.certificate.certextensions.CertificateExtension#getValue(EndEntityInformation, CA, CertificateProfile, PublicKey,
     *      PublicKey)
     */
    public DEREncodable getValue(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey, PublicKey caPublicKey)
            throws CertificateExtensionException, CertificateExtentionConfigurationException {

        if (dEREncodable == null) {
            String encoding = getProperties().getProperty(PROPERTY_ENCODING);
            encoding = StringUtils.trim(encoding); // Ignore any spaces in the end
            String strnvalues = getProperties().getProperty(PROPERTY_NVALUES);
            String value = null;

            int nvalues;

            if (strnvalues == null || strnvalues.trim().equals("")) {
                nvalues = 0;
            } else {
                nvalues = Integer.parseInt(strnvalues);
            }

            if (nvalues < 1) {
                value = getProperties().getProperty(PROPERTY_VALUE);
                if (value == null || value.trim().equals("")) {
                    value = getProperties().getProperty(PROPERTY_VALUE + "1");
                }
                dEREncodable = parseValue(encoding, value);
            } else {
                ASN1EncodableVector ev = new ASN1EncodableVector();
                for (int i = 1; i <= nvalues; i++) {
                    value = getProperties().getProperty(PROPERTY_VALUE + Integer.toString(i));
                    DEREncodable derval = parseValue(encoding, value);
                    ev.add(derval);
                }
                dEREncodable = new DERSequence(ev);
            }
        }

        return dEREncodable;
    }

    private DEREncodable parseValue(String encoding, String value) throws CertificateExtentionConfigurationException, CertificateExtensionException {

        DEREncodable toret = null;

        if (!encoding.equalsIgnoreCase(ENCODING_DERNULL) && (value == null || value.trim().equals(""))) {
            throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.incorrectvalue", Integer.valueOf(getId())));
        }

        if (encoding.equalsIgnoreCase(ENCODING_DERBITSTRING)) {
            toret = parseDERBitString(value);
        } else if (encoding.equalsIgnoreCase(ENCODING_DERINTEGER)) {
            toret = parseDERInteger(value);
        } else if (encoding.equalsIgnoreCase(ENCODING_DEROCTETSTRING)) {
            toret = parseDEROctetString(value);
        } else if (encoding.equalsIgnoreCase(ENCODING_DERBOOLEAN)) {
            toret = parseDERBoolean(value);
        } else if (encoding.equalsIgnoreCase(ENCODING_DEROID)) {
            toret = parseDEROID(value);
        } else if (encoding.equalsIgnoreCase(ENCODING_DERPRINTABLESTRING)) {
            toret = parseDERPrintableString(value);
        } else if (encoding.equalsIgnoreCase(ENCODING_DERUTF8STRING)) {
            toret = parseDERUTF8String(value);
        } else if (encoding.equalsIgnoreCase(ENCODING_DERIA5STRING)) {
            toret = parseDERIA5String(value);
        } else if (encoding.equalsIgnoreCase(ENCODING_DERNULL)) {
            toret = new DERNull();
        } else if (encoding.equalsIgnoreCase(ENCODING_DEROBJECT)) {
            toret = parseHexEncodedDERObject(value);
        } else {
            throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.incorrectenc", encoding,
                    Integer.valueOf(getId())));
        }
        return toret;
    }

    private DEREncodable parseDERBitString(String value) throws CertificateExtentionConfigurationException {
        DEREncodable retval = null;
        try {
            BigInteger bigInteger = new BigInteger(value, 2);
            int padBits = value.length() - 1 - value.lastIndexOf("1");
            if (padBits == 8) {
                padBits = 0;
            }
            byte[] byteArray = bigInteger.toByteArray();
            if (byteArray[0] == 0) {
                // Remove empty extra byte
                byte[] shorterByteArray = new byte[byteArray.length - 1];
                for (int i = 0; i < shorterByteArray.length; i++) {
                    shorterByteArray[i] = byteArray[i + 1];
                }
                byteArray = shorterByteArray;
            }
            retval = new DERBitString(byteArray, padBits);
        } catch (NumberFormatException e) {
            throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue", value,
                    Integer.valueOf(getId())));
        }

        return retval;
    }

    private DEREncodable parseDEROID(String value) throws CertificateExtentionConfigurationException {
        DEREncodable retval = null;
        try {
            retval = new DERObjectIdentifier(value);
        } catch (Exception e) {
            throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue", value,
                    Integer.valueOf(getId())));
        }

        return retval;
    }

    private DEREncodable parseDERInteger(String value) throws CertificateExtentionConfigurationException {
        DEREncodable retval = null;
        try {
            BigInteger intValue = new BigInteger(value, 10);
            retval = new DERInteger(intValue);
        } catch (NumberFormatException e) {
            throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue", value,
                    Integer.valueOf(getId())));
        }

        return retval;
    }

    private DEREncodable parseDEROctetString(String value) throws CertificateExtentionConfigurationException {
        DEREncodable retval = null;
        if (value.matches("^\\p{XDigit}*")) {
            byte[] bytes = Hex.decode(value);
            retval = new DEROctetString(bytes);
        } else {
            throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue", value,
                    Integer.valueOf(getId())));
        }
        return retval;
    }

    /**
     * Tries to read the hex-string as an DERObject. If it contains more than one DEREncodable object, return a DERSequence of the objects.
     */
    private DEREncodable parseHexEncodedDERObject(String value) throws CertificateExtentionConfigurationException {
        DEREncodable retval = null;
        if (value.matches("^\\p{XDigit}*")) {
            byte[] bytes = Hex.decode(value);
            try {
                ASN1InputStream ais = new ASN1InputStream(bytes);
                DEREncodable firstObject = ais.readObject();
                if (ais.available() > 0) {
                    ASN1EncodableVector ev = new ASN1EncodableVector();
                    ev.add(firstObject);
                    while (ais.available() > 0) {
                        ev.add(ais.readObject());
                    }
                    retval = new DERSequence(ev);
                } else {
                    retval = firstObject;
                }
            } catch (Exception e) {
                throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue", value,
                        Integer.valueOf(getId())));
            }
        } else {
            throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue", value,
                    Integer.valueOf(getId())));
        }
        return retval;
    }

    private DEREncodable parseDERBoolean(String value) throws CertificateExtentionConfigurationException {
        DEREncodable retval = null;
        if (value.equalsIgnoreCase("TRUE")) {
            retval = DERBoolean.TRUE;
        }

        if (value.equalsIgnoreCase("FALSE")) {
            retval = DERBoolean.FALSE;
        }

        if (retval == null) {
            throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue", value,
                    Integer.valueOf(getId())));
        }

        return retval;
    }

    private DEREncodable parseDERPrintableString(String value) throws CertificateExtentionConfigurationException {
        try {
            return new DERPrintableString(value, true);
        } catch (java.lang.IllegalArgumentException e) {
            throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue", value,
                    Integer.valueOf(getId())));
        }
    }

    private DEREncodable parseDERUTF8String(String value) {
        return new DERUTF8String(value);
    }

    private DEREncodable parseDERIA5String(String value) throws CertificateExtentionConfigurationException {
        try {
            return new DERIA5String(value, true);
        } catch (java.lang.IllegalArgumentException e) {
            throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue", value,
                    Integer.valueOf(getId())));
        }
    }

}
