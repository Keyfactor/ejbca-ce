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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.CeSecoreNameStyle;

/**
 * Extension for Name Constraints.
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.10">RFC 5280</a>
 *
 * For storing Name Constraints, an internal encoded form is used. The format is "type-id:data"
 * where data is either a regular string or hex-encoded data, depending on the type.
 * Use parseNameConstraintList to convert human-readable strings into encoded strings.
 *
 * @version $Id$
 */
public class NameConstraint extends StandardCertificateExtension {

    private static final long serialVersionUID = 1L;

    @Override
    public void init(CertificateProfile certProf) {
        super.setOID(Extension.nameConstraints.getId());
        super.setCriticalFlag(certProf.getNameConstraintsCritical());
    }

    @Override
    public ASN1Encodable getValue(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException {
        NameConstraints nc = null;

        if (!(ca instanceof X509CA)) {
            throw new CertificateExtensionException("Can't issue non-X509 certificate with Name Constraint");
        }

        final ExtendedInformation ei = userData.getExtendedInformation();
        if (ei != null) {
            final List<String> permittedNames = ei.getNameConstraintsPermitted();
            final List<String> excludedNames = ei.getNameConstraintsExcluded();

            // Do not include an empty name constraints extension
            if (permittedNames != null || excludedNames != null) {
                final GeneralSubtree[] permitted = toGeneralSubtrees(permittedNames);
                final GeneralSubtree[] excluded = toGeneralSubtrees(excludedNames);

                nc = new NameConstraints(permitted, excluded);
            }
        }

        return nc;
    }

    /**
     * Converts a list of encoded strings of Name Constraints into ASN1 GeneralSubtree objects.
     * This is needed when creating an BouncyCastle ASN1 NameConstraint object for inclusion
     * in a certificate.
     */
    public static GeneralSubtree[] toGeneralSubtrees(List<String> list) {
        if (list == null) {
            return null;
        }

        GeneralSubtree[] ret = new GeneralSubtree[list.size()];
        int i = 0;
        for (String entry : list) {
            int type = getNameConstraintType(entry);
            Object data = getNameConstraintData(entry);
            GeneralName genname;
            switch (type) {
            case GeneralName.dNSName:
            case GeneralName.rfc822Name:
                genname = new GeneralName(type, (String)data);
                break;
            case GeneralName.directoryName:
                genname = new GeneralName(new X500Name(CeSecoreNameStyle.INSTANCE, (String)data));
                break;
            case GeneralName.iPAddress:
                genname = new GeneralName(type, new DEROctetString((byte[])data));
                break;
            default:
                throw new UnsupportedOperationException("Encoding of name constraint type "+type+" is not implemented.");
            }
            ret[i++] = new GeneralSubtree(genname);
        }
        return ret;
    }

    /**
     * Returns the GeneralName type code for an encoded Name Constraint.
     */
    private static int getNameConstraintType(String encoded) {
        String typeString = encoded.split(":", 2)[0];
        if ("iPAddress".equals(typeString)) {
            return GeneralName.iPAddress;
        }
        if ("dNSName".equals(typeString)) {
            return GeneralName.dNSName;
        }
        if ("directoryName".equals(typeString)) {
            return GeneralName.directoryName;
        }
        if ("rfc822Name".equals(typeString)) {
            return GeneralName.rfc822Name;
        }
        throw new UnsupportedOperationException("Unsupported name constraint type "+typeString);
    }

    /**
     * Returns the GeneralName data (as a byte array or String) from an encoded string.
     */
    private static Object getNameConstraintData(String encoded) {
        int type = getNameConstraintType(encoded);
        String data = encoded.split(":", 2)[1];

        switch (type) {
        case GeneralName.dNSName:
        case GeneralName.directoryName:
        case GeneralName.rfc822Name:
            return data;
        case GeneralName.iPAddress:
            try {
                return Hex.decodeHex(data.toCharArray());
            } catch (DecoderException e) {
                throw new IllegalStateException("internal name constraint data could not be decoded as hex", e);
            }
        default:
            throw new UnsupportedOperationException("Unsupported name constraint type "+type);
        }
    }

    /**
     * Parses a single name constraint entry in human-readable form into
     * an encoded string for database storage etc. The intention is to make it possible
     * to change the human readable form at a later point.
     *
     * This format is essentially a hex string representation of a RFC 5280 GeneralName,
     * but only DNS Names and IP Addresses are supported so far.
     *
     * @throws CertificateExtensionException if the string can not be parsed.
     */
    public static String parseNameConstraintEntry(String str) throws CertificateExtensionException {
        if (str.matches("^([0-9]+\\.){3,3}([0-9]+)/[0-9]+$") ||
            str.matches("^[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F:]*/[0-9]+$")) {
            // IPv4 or IPv6 address
            try {
                String[] pieces = str.split("/", 2);
                byte[] addr = InetAddress.getByName(pieces[0]).getAddress();
                byte[] encoded = new byte[2*addr.length]; // will hold address and netmask
                System.arraycopy(addr, 0, encoded, 0, addr.length);

                // The second half in the encoded form is the netmask
                int netmask = Integer.parseInt(pieces[1]);
                if (netmask > 8*addr.length) {
                    throw new CertificateExtensionException("Netmask is too large: "+str);
                }
                for (int i = 0; i < netmask; i++) {
                    encoded[addr.length + i/8] |= 1 << (7 - i%8);
                }
                // Clear host part from IP address
                for (int i = netmask; i < 8*addr.length; i++) {
                    encoded[i/8] &= ~(1 << (7 - i%8));
                }
                return "iPAddress:"+Hex.encodeHexString(encoded);
            } catch (UnknownHostException e) {
                throw new CertificateExtensionException("Failed to parse IP address in name constraint: "+str, e);
            }
        } else if (str.matches("^([0-9]+\\.){3,3}([0-9]+)$")) {
            // IP address without netmask. This is not a valid DNS name, so catch it here.
            throw new CertificateExtensionException("Name constraint entry with IP address is missing a netmask: "+str+". Use /32 to match only this address.");
        } else if (str.matches("^\\.?([a-zA-Z0-9_-]+\\.)*[a-zA-Z0-9_-]+$")) {
            // DNS name (it can start with a ".", this means "all subdomains")
            return "dNSName:"+str;
        } else if (str.matches("^[^=,]*@[a-zA-Z0-9_.\\[\\]:-]+$")) {
            String email = str;
            // RFC 822 Name (i.e. e-mail)
            if (str.startsWith("@")) {
                // In EJBCA, rfc822Names without a user part start with @ to distinguish them from domain names.
                // This is not the case in the encoded form.
                email = email.substring(1);
            }
            return "rfc822Name:"+email;
        } else if (str.contains("=")) {
            // Directory name
            return "directoryName:" + new X500Name(CeSecoreNameStyle.INSTANCE, str).toString();
        } else {
            throw new CertificateExtensionException("Cannot parse name constraint entry (only DNS Name, RFC 822 Name, Directory Name, IPv4/Netmask and IPv6/Netmask are supported): "+str);
        }
    }

    /**
     * Parses human readable name constraints, one entry per line, into a list of encoded name constraints.
     * @see parseNameConstraintEntry
     */
    public static List<String> parseNameConstraintsList(String input) throws CertificateExtensionException {
        List<String> encodedNames = new ArrayList<>();
        if (input != null) {
            String[] pieces = input.split("\n");
            for (String piece : pieces) {
                piece = piece.trim();
                if (!piece.isEmpty()) {
                    encodedNames.add(NameConstraint.parseNameConstraintEntry(piece));
                }
            }
        }
        return encodedNames;
    }

    /**
     * Formats an encoded name constraint from parseNameConstraintEntry into human-readable form.
     */
    public static String formatNameConstraintEntry(String encoded) {
        if (encoded == null) {
            return "";
        }

        int type = getNameConstraintType(encoded);
        Object data = getNameConstraintData(encoded);

        switch (type) {
        case GeneralName.dNSName:
        case GeneralName.directoryName:
            return (String)data; // not changed during encoding
        case GeneralName.iPAddress:
            byte[] bytes = (byte[])data;
            byte[] ip = new byte[bytes.length/2];
            byte[] netmaskBytes = new byte[bytes.length/2];
            System.arraycopy(bytes, 0, ip, 0, ip.length);
            System.arraycopy(bytes, ip.length, netmaskBytes, 0, netmaskBytes.length);

            int netmask = 0;
            for (int i = 0; i < 8*netmaskBytes.length; i++) {
                final boolean one = (netmaskBytes[i/8] >> (7 - i%8) & 1) == 1;
                if (one && netmask == i) {
                    netmask++; // leading ones
                } else if (one) {
                    // trailings ones = error!
                    throw new IllegalArgumentException("Unsupported netmask with mixed ones/zeros");
                }
            }

            try {
                return InetAddress.getByAddress(ip).getHostAddress() + "/" + netmask;
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException(e);
            }
        case GeneralName.rfc822Name:
            // Prepend @ is it's only the domain part to distinguish from DNS names
            String str = (String)data;
            return (str.contains("@") ? str : "@"+str);
        default:
            throw new UnsupportedOperationException("Unsupported name constraint type "+type);
        }
    }

    /**
     * Formats an encoded list of name constraints into a human-readable list, with one entry per line.
     * @return a newline-separated string of encoded name constraints
     */
    public static String formatNameConstraintsList(final List<String> encodedList) {
        final StringBuilder sb = new StringBuilder();
        if (encodedList != null) {
            boolean first = true;
            for (String encodedName : encodedList) {
                if (!first) {
                    sb.append('\n');
                }
                first = false;
                sb.append(formatNameConstraintEntry(encodedName)); // notice the call to formatNameConstraintEntry, so this is different from StringUtils.join
            }
        }
        return sb.toString();
    }
}
