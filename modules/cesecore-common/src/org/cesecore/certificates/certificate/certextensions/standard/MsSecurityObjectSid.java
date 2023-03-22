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

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

import com.keyfactor.util.CertTools;

import net.tirasa.adsddl.ntsd.SID;

/**
 * Basic Extension added for Microsoft szOID_NTDS_CA_SECURITY_EXT against ADCS vulnerability CVE-2022-26931
 */
public class MsSecurityObjectSid extends StandardCertificateExtension {
    
    private static final long serialVersionUID = 1L;

    @Override
    public void init(final CertificateProfile certProf) {
        super.setOID(CertTools.OID_MS_SZ_OID_NTDS_CA_SEC_EXT);
        super.setCriticalFlag(false);
    }
    
    @Override
    public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) {
        if(subject.getExtendedInformation()==null) {
            return null;
        }
        // we may set null in EJBCARequest in MSAE according to msPKI-Enrollment-Flag value
        // also value is set to customData instead of extensionData, which is used for custom extensions
        // this is to avoid interfering with instances with same extensions already added as custom extension
        String extensionValue = subject.getExtendedInformation()
                .getCustomData(CertTools.OID_MS_SZ_OID_NTDS_CA_SEC_EXT);
        if(extensionValue==null) {
            return null;
        }
        byte[] objectSidValue = Hex.decode(extensionValue);
        return DERSequence.getInstance(serializeObjectSidExtension(objectSidValue));             
    }
    
    private byte[] serializeObjectSidExtension(byte[] objectSid) {
//      Microsoft szOID_NTDS_CA_SECURITY_EXT for ADCS vuln. CVE-2022-26931
//      format https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-winerrata/c39fd72a-da21-4b13-b329-c35d61f74a60
//             Format: The following is the ASN.1 format ([X690]) for this attribute.
//             OtherName ::= SEQUENCE {
//             type-id szOID_NTDS_OBJECTSID,
//             value    octet string}
        ASN1EncodableVector otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier(CertTools.OID_MS_SZ_OID_NTDS_CA_SEC_EXT + ".1"));
        otherName.add(new DERTaggedObject(0, new DEROctetString(SID.parse(objectSid).toString().getBytes())));
        // alternative: SID.parse(adObject.getObjectSID()).toByteArray()) to use machine readable SID
        
        byte[] value;
        try {
            value = new DERSequence(new DERSequence(otherName)).getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("MsSecurityObjectSid extension could not be encoded.", e);
        }
        value[2] = (byte) 0xA0; // ASN1EncodableVector could not be serialized as DERTaggedObject
        return value;
    }
    
}