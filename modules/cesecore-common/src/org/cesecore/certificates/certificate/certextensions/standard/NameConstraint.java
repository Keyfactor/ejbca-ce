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
import java.util.List;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Extension for Name Constraints.
 * <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.10">RFC 5280</a>
 * 
 * @version $Id$
 */
public class NameConstraint extends StandardCertificateExtension {

    @Override
    public void init(CertificateProfile certProf) {
        super.setOID(Extension.nameConstraints.getId());
        super.setCriticalFlag(certProf.getNameConstraintsCritical());
    }

    @Override
    public ASN1Encodable getValue(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException {
        NameConstraints nc = null;
        if ((certProfile.getType() == CertificateConstants.CERTTYPE_SUBCA ||
            certProfile.getType() == CertificateConstants.CERTTYPE_ROOTCA) &&
            ca instanceof X509CA) {
            
            X509CAInfo x509ca = (X509CAInfo)ca.getCAInfo();
            GeneralSubtree[] permitted = toGeneralSubtrees(x509ca.getNameConstraintsPermitted());
            GeneralSubtree[] excluded = toGeneralSubtrees(x509ca.getNameConstraintsExcluded());
            
            // Do not include an empty name constraints extension
            if (permitted.length != 0 || excluded.length != 0) {
                nc = new NameConstraints(permitted, excluded);
            }
        }
        return nc;
    }
    
    public static GeneralSubtree[] toGeneralSubtrees(List<String> list) {
        if (list == null) {
            return new GeneralSubtree[0];
        }
        
        GeneralSubtree[] ret = new GeneralSubtree[list.size()];
        int i = 0;
        for (String entry : list) {
            int type = getNameConstraintType(entry);
            Object data = getNameConstraintData(entry);
            GeneralName genname;
            switch (type) {
            case GeneralName.dNSName:
                genname = new GeneralName(type, (String)data);
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
    
    public static int getNameConstraintType(String encoded) {
        String typeString = encoded.split(":", 2)[0];
        if ("iPAddress".equals(typeString)) return GeneralName.iPAddress;
        if ("dNSName".equals(typeString)) return GeneralName.dNSName;
        throw new UnsupportedOperationException("Unsupported name constraint type "+typeString);
    }

    private static Object getNameConstraintData(String encoded) {
        int type = getNameConstraintType(encoded);
        String data = encoded.split(":", 2)[1];
        
        switch (type) {
        case GeneralName.dNSName:
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
                    throw new CertificateExtensionException("Netmask is too large");
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
                throw new CertificateExtensionException("Failed to parse IP address in name constraint", e);
            }
        } else if (str.matches("^\\.?([a-zA-Z0-9_-]+\\.)*[a-zA-Z0-9_-]+$")) {
            // DNS name (it can start with a ".", this means "all subdomains")
            return "dNSName:"+str;
        } else {
            throw new CertificateExtensionException("Cannot parse name constraint entry, only IPv4/6 addresses with a /netmask and DNS names are supported. Input string: "+str);
        }
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
        default:
            throw new UnsupportedOperationException("Unsupported name constraint type "+type);
        }
    }
    
}
