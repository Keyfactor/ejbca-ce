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
package org.cesecore.util;

import static org.junit.Assert.assertTrue;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Test;

import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.CertTools;

/**
 * Tests that we can produce DNs with wither UTF8String (which should be used according to RFC5280), or configured with more legacy PrintableString.
 */
public class PrintableStringNameStyleTest {

    private static Logger log = Logger.getLogger(PrintableStringNameStyleTest.class);
    
    /**
     * Tests encoding DN attributes as UTF-8 or printable string
     */
    @Test
    public void testPrintableStringDN() throws Exception {
        log.trace(">testPrintableStringDN()");
        
        final String dnstr = "C=SE,O=Test,CN=Test,UniqueIdentifier=N62892,CertificationID=BSI-K-TR-1234-2023";
        
        final X500Name xn1 = CertTools.stringToBcX500Name(dnstr, new CeSecoreNameStyle(), false);
        assertTrue("When using CeSecoreNameStyle, C was not of PrintableString type", xn1.getRDNs()[0].getFirst().getValue() instanceof DERPrintableString);
        assertTrue("When using CeSecoreNameStyle, O was not of UTF8String type", xn1.getRDNs()[1].getFirst().getValue() instanceof DERUTF8String);
        assertTrue("When using CeSecoreNameStyle, CN was not of UTF8String type", xn1.getRDNs()[2].getFirst().getValue() instanceof DERUTF8String);
        assertTrue("When using CeSecoreNameStyle, UniqueIdentifier was not of UTF8String type", xn1.getRDNs()[3].getFirst().getValue() instanceof DERUTF8String);
        assertTrue("When using CeSecoreNameStyle, CertificationID was not of ASN1Sequence type", xn1.getRDNs()[4].getFirst().getValue() instanceof ASN1Sequence);
        
        final X500Name xn2 = CertTools.stringToBcX500Name(dnstr, new PrintableStringNameStyle(), false);
        assertTrue("When using PrintableStringNameStyle, C was not of PrintableString type", xn2.getRDNs()[0].getFirst().getValue() instanceof DERPrintableString);
        assertTrue("When using PrintableStringNameStyle, O was not of PrintableString type", xn2.getRDNs()[1].getFirst().getValue() instanceof DERPrintableString);
        assertTrue("When using PrintableStringNameStyle, CN was not of PrintableString type", xn2.getRDNs()[2].getFirst().getValue() instanceof DERPrintableString);
        assertTrue("When using CeSecoreNameStyle, UniqueIdentifier was not of PrintableString type", xn2.getRDNs()[3].getFirst().getValue() instanceof DERPrintableString);
        assertTrue("When using CeSecoreNameStyle, CertificationID was not of ASN1Sequence type", xn2.getRDNs()[4].getFirst().getValue() instanceof ASN1Sequence);
        
        log.trace("<testPrintableStringDN()");
    }

}
