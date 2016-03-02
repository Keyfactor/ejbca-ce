/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package se.primekey.ejbca.autoenroll;

/**
 * 
 * @version $Id$
*/
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

public class ASN1 {
    static String dump(ASN1Object asn1obj, PKCS10Info info, boolean bPrintToSysOut) {
        return dump(asn1obj, info, bPrintToSysOut, 0, null, null);
    }

    static String dump(ASN1Object asn1obj, PKCS10Info info, boolean bPrintToSysOut, int level, String strOid, ASN1Sequence seq1) {
        String retval = null;

        StringBuilder sb = new StringBuilder("");
        for (int i = 0; i < level; i++) {
            sb.append("\t");
        }

        if (asn1obj instanceof ASN1Set) {
            ASN1Set asn1set = (ASN1Set) asn1obj;

            if (bPrintToSysOut)
                System.out.println(sb.toString() + asn1set.getClass().getName() + ": " + asn1set.toString());
            String strOidInSet = null;
            @SuppressWarnings("unchecked")
            Enumeration<Object> objects = asn1set.getObjects();
            while (objects.hasMoreElements()) {
                Object nextElement = objects.nextElement();
                if (nextElement instanceof ASN1Object) {
                    String ret = dump((ASN1Object) nextElement, info, bPrintToSysOut, level + 1, strOidInSet, seq1);
                    if (null != ret) {
                        strOidInSet = ret;
                    }
                } else {
                    if (bPrintToSysOut)
                        System.out.println(sb.toString() + "*** obj: [" + nextElement + "], class: " + nextElement.getClass().getName());
                }
            }
        } else if (asn1obj instanceof ASN1Sequence) {
            ASN1Sequence asn1seq = (ASN1Sequence) asn1obj;

            //            if (bPrintToSysOut) System.out.println(sb.toString() + asn1seq.getClass().getName() + ": " + asn1seq.toString());
            if (bPrintToSysOut)
                System.out.println(sb.toString() + asn1seq.getClass().getName());
            @SuppressWarnings("unchecked")
            Enumeration<Object> objects = asn1seq.getObjects();
            String strOidInSeq = null;
            while (objects.hasMoreElements()) {
                Object nextElement = objects.nextElement();

                if (nextElement instanceof ASN1Object) {
                    String ret = dump((ASN1Object) nextElement, info, bPrintToSysOut, level + 1, strOidInSeq, asn1seq);
                    if (null != ret) {
                        strOidInSeq = ret;
                    }
                } else {
                    if (bPrintToSysOut)
                        System.out.println(sb.toString() + "*** obj: [" + nextElement + "], class: " + nextElement.getClass().getName());
                }
            }
        } else if (asn1obj instanceof DERTaggedObject) {
            DERTaggedObject dto = (DERTaggedObject) asn1obj;
            if (bPrintToSysOut)
                System.out.println(sb.toString() + asn1obj.getClass().getName() + ", Tag No: " + dto.getTagNo() + " : [" + dto + "]");
            dump((ASN1Object) dto.getObject(), info, bPrintToSysOut, level + 1, null, seq1);
        } else if (asn1obj instanceof DEROctetString) {
            DEROctetString octetString = (DEROctetString) asn1obj;

            if (bPrintToSysOut)
                System.out.println(
                        sb.toString() + asn1obj.getClass().getName() + ": [" + octetString.getOctets().length + "]: " + octetString.toString());

            if (null != strOid) {
                if (0 == strOid.compareTo(Extension.keyUsage.getId())) // Key Usage
                {
                    /**
                     * TODO Is this correct?
                     * ie, that the first byte determines the number of following bytes to use?
                     */
                    byte[] bytes = octetString.getOctets();
                    int val = valFromBytes(bytes);
                    //                    if (bPrintToSysOut) System.out.println("val: " + val);
                    String strTemp = OctetStringToKeyUsageString(val);
                    if (bPrintToSysOut)
                        System.out.println(sb.toString() + strTemp);
                } else if (0 == strOid.compareTo(Extension.extendedKeyUsage.getId())) // Extended Key Usage 
                {
                    try {
                        //                        if (bPrintToSysOut) System.out.println(sb.toString() + ASN1Dump.dumpAsString(octetString, true));
                        if (bPrintToSysOut)
                            System.out.println(decodeSequence(octetString, sb.toString()));
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }

                } else if (0 == strOid.compareTo("1.3.6.1.4.1.311.20.2")) // Enroll Certtype Extension
                {
                    // May not always be found.
                    // Found in original templates, but not in duplicates (2003).
                    byte[] bytes = octetString.getOctets();
                    final String strCertificateTemplateName = calculateAscString(bytes, 0, bytes.length);
                    info.setCertificateTemplateName(strCertificateTemplateName);
                    if (bPrintToSysOut)
                        System.out.println(sb.toString() + strCertificateTemplateName);
                } else if (0 == strOid.compareTo("1.3.6.1.4.1.311.21.7")) // Certificate Template
                {
                    // May not always be found.
                    // Found in duplicates (2003) but not original templates (2000).
                    final String strCertificateTemplateOid = decodeSequence(octetString, sb.toString());
                    info.setCertificateTemplateOid(strCertificateTemplateOid);
                    if (bPrintToSysOut)
                        System.out.println(sb.toString() + strCertificateTemplateOid);
                } else if (0 == strOid.compareTo("1.2.840.113549.1.9.15")) // S/Mime capabilities 
                {
                    if (bPrintToSysOut)
                        System.out.println(decodeSequence(octetString, sb.toString()));
                } else if (0 == strOid.compareTo("1.3.6.1.4.1.311.21.10")) // Application Policies extension
                {
                    if (bPrintToSysOut)
                        System.out.println(decodeSequence(octetString, sb.toString()));
                } else if (0 == strOid.compareTo("2.5.29.17")) // SubjectAlternativeName
                {
                    if (bPrintToSysOut)
                        System.out.println(decodeSequence(octetString, sb.toString()));
                } else if (0 == strOid.compareTo("2.5.29.14")) // SubjectKeyIdentifier
                {
                    if (bPrintToSysOut)
                        System.out.println(decodeSequence(octetString, sb.toString()));
                } else {
                    if (bPrintToSysOut)
                        System.out.println(decodeSequence(octetString, sb.toString()));
                }
            }
        } else if (asn1obj instanceof ASN1ObjectIdentifier) {
            ASN1ObjectIdentifier objIdent = (ASN1ObjectIdentifier) asn1obj;
            String name = OidMap.getOidName(objIdent.toString());
            if (null != name) {
                if (bPrintToSysOut)
                    System.out.println(sb.toString() + name + " [" + objIdent + "] : " + objIdent.getClass().getName());
                retval = objIdent.toString();
            } else {
                if (bPrintToSysOut)
                    System.out.println(sb.toString() + objIdent + " : " + objIdent.getClass().getName());
            }
        } else if ((asn1obj instanceof ASN1Boolean) || (asn1obj instanceof ASN1Integer) || (asn1obj instanceof DERNull)) {
            if (bPrintToSysOut)
                System.out.println(sb.toString() + asn1obj + " : " + asn1obj.getClass().getName());
        } else if (asn1obj instanceof DERUTF8String) {
            if (bPrintToSysOut)
                System.out.println(sb.toString() + asn1obj + " : " + asn1obj.getClass().getName());
        } else if (asn1obj instanceof DERIA5String) {
            if (bPrintToSysOut)
                System.out.println(sb.toString() + asn1obj + " : " + asn1obj.getClass().getName());
        } else if (asn1obj instanceof DERPrintableString) {
            if (bPrintToSysOut)
                System.out.println(sb.toString() + asn1obj + " : " + asn1obj.getClass().getName());
        } else if (asn1obj instanceof DERBitString) {
            DERBitString dbs = (DERBitString) asn1obj;
            if (bPrintToSysOut)
                System.out.println(sb.toString() + asn1obj.getClass().getName() + ", (Length, Padbits, intValue) = " + dbs.getBytes().length + ", "
                        + dbs.getPadBits() + ", " + dbs.intValue() + " : [" + dbs.toString() + "]");
            ASN1Dump.dumpAsString(dbs, true);
        } else {
            if (bPrintToSysOut)
                System.out.println(sb.toString() + "*** obj: [" + asn1obj + "], class: " + asn1obj.getClass().getName());
        }

        return retval;
    }

    static private String OctetStringToKeyUsageString(int val) {
        StringBuilder sb1 = new StringBuilder();
        if (0 != (val & KeyUsage.digitalSignature)) {
            sb1.append("Digital Signature");
        }
        if (0 != (val & KeyUsage.nonRepudiation)) {
            sb1.append(", Non-repudiation");
        }
        if (0 != (val & KeyUsage.keyEncipherment)) {
            sb1.append(", Key Encipherment");
        }
        if (0 != (val & KeyUsage.dataEncipherment)) {
            sb1.append(", Data Encipherment");
        }
        if (0 != (val & KeyUsage.keyAgreement)) {
            sb1.append(", Key Agreement");
        }
        if (0 != (val & KeyUsage.keyCertSign)) {
            sb1.append(", Key Certificate Signing");
        }
        if (0 != (val & KeyUsage.cRLSign)) {
            sb1.append(", CRL Signing");
        }
        if (0 != (val & KeyUsage.encipherOnly)) {
            sb1.append(", Encipher Only");
        }
        if (0 != (val & KeyUsage.decipherOnly)) {
            sb1.append(", Decipher Only");
        }
        String strTemp = sb1.toString();
        if (strTemp.startsWith(", ")) {
            strTemp = strTemp.substring(2);
        }
        return strTemp;
    }

    private static int valFromBytes(byte[] bytes) {
        int retval = 0;
        int len = (int) bytes[0];

        assert (len < bytes.length);

        for (int i = 1; i <= len; i++) {
            retval = (int) (bytes[i] & 0xff) + (retval << 8);
        }

        return retval;
    }

    // From org.bouncycastle.asn1.util.ASN1Dump
    private static String calculateAscString(byte[] bytes, int off, int len) {
        StringBuilder buf = new StringBuilder();

        for (int i = off; i != off + len; i++) {
            if (bytes[i] >= ' ' && bytes[i] <= '~') {
                buf.append((char) bytes[i]);
            }
        }

        return buf.toString();
    }

    static String decodeSequence(DEROctetString octetString, String indent) {
        StringBuilder sb0 = new StringBuilder();

        byte[] bytes = octetString.getOctets();

        int index = 0;

        // A Sequence
        if (0x30 == bytes[index]) {
            decodeSequence_(bytes, index, sb0, indent);
        }

        return sb0.toString();
    }

    static private int decodeSequence_(byte[] bytes, int index, StringBuilder sb0, String indent) {
        // Length of sequence
        int lenSeq = bytes[index + 1];
        if (0 != (bytes[index + 1] & 0x0080)) {
            // number of bytes contributing to length
            int numBytesInLength = (int) (bytes[index + 1] & 0x007f);
            //                System.out.println("numBytesInLength = " + numBytesInLength);

            lenSeq = 0;
            for (int k = 0; k < numBytesInLength; k++) {
                int temp = (int) (bytes[index + 2 + k] & 0x00ff);
                lenSeq *= 256;
                lenSeq += temp;
            }
            index += 2 + numBytesInLength;
        } else {
            index += 2;
        }

        final int indexEnd = lenSeq + index;
        //        System.out.println("index = " + index + ", lenSeq = " + lenSeq + ", lenString = " + bytes.length + ", indexEnd = " + indexEnd);
        assert (indexEnd <= bytes.length);

        while (index < indexEnd) {
            //            System.out.println("\tindex = " + index + ", lenSeq = " + lenSeq + ", lenString = " + bytes.length + ", indexEnd = " + indexEnd);
            StringBuilder sb = new StringBuilder();

            // A sequence
            if (0x30 == bytes[index]) {
                index = decodeSequence_(bytes, index, sb0, indent + "\t");
                //                System.out.println("*** index = " + index + " [" + sb0 + "]");
            }
            // An Object Identifier
            else if (0x06 == bytes[index]) {
                int lenOid = ((int) bytes[index + 1] & 0x00ff);
                //                System.out.println("LenOID = " + lenOid + ", index = " + index + ", lenSeq = " + lenSeq + ", lenString = " + bytes.length);

                for (int j = 0; j < lenOid; j++) {
                    if (j > 0) {
                        sb.append(".");
                    }

                    int val = bytes[j + index + 2] & 0x00ff;
                    // If the high bit is set, then use lower 7 bits of two bytes to determine value.
                    if (0 != (bytes[j + index + 2] & 0x0080)) {
                        long lval = 0;
                        while (0 != (bytes[j + index + 2] & 0x0080)) {
                            lval += (int) (bytes[j + index + 2] & 0x007f);
                            lval *= 128;
                            j++;
                        }
                        // Last byte indicated by leading 0.
                        lval += (int) (bytes[j + index + 2] & 0x007f);

                        sb.append(lval);
                    } else {
                        if (j == 0) {
                            if (val >= 40) {
                                int val1 = val / 40;
                                int val2 = val % 40;

                                sb.append(val1);
                                sb.append(".");
                                val = val2;
                            }
                        }

                        sb.append(val);
                    }
                }

                String strOid = sb.toString();
                if (sb0.length() > 0) {
                    sb0.append("\n");
                }
                sb0.append(indent);
                String strOidName = OidMap.getOidName(strOid);
                if (null != strOidName) {
                    sb0.append("[").append(strOid).append("]: ").append(OidMap.getOidName(strOid));
                } else {
                    sb0.append("[").append(strOid).append("]");
                }

                index += lenOid + 2;
            } else // Assume anything left are parameters?
            {
                sb.append("Parameters: ");
                for (int m = index; m < indexEnd; m++) {
                    sb.append("\n").append(indent).append("\t").append(m).append(": [").append((int) (bytes[m] & 0x00ff)).append("] [")
                            .append((char) bytes[m]).append("]");
                }
                sb0.append("\n").append(indent);
                sb0.append(sb);

                index = indexEnd;
            }
        }

        //        System.out.println("On return index = " + index + ", indexEnd = " + indexEnd + "\t: [" + sb0.toString() + "]");
        return indexEnd;
    }

}
