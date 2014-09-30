/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.util;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;

/**
 * Helpers used by different tests, that does not invoke EJBs.
 * 
 * TODO: Move this class to one of the test libs
 *  
 * @version $Id$
 */
public class NonEjbTestTools {

    public static byte[] generatePKCS10Req(String dn, String password) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidAlgorithmParameterException, IOException, OperatorCreationException {
        // Generate keys
    	KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);            

        // Create challenge password attribute for PKCS10
        // Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
        //
        // Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
        //    type    ATTRIBUTE.&id({IOSet}),
        //    values  SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{\@type})
        // }
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword); 
        ASN1EncodableVector values = new ASN1EncodableVector();
        values.add(new DERUTF8String(password));
        vec.add(new DERSet(values));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERSequence(vec));
        DERSet set = new DERSet(v);
        // Create PKCS#10 certificate request
        PKCS10CertificationRequest p10request = CertTools.genPKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX500Name(dn), keys.getPublic(), set, keys.getPrivate(), null);
        return p10request.toASN1Structure().getEncoded();        
    }
}
