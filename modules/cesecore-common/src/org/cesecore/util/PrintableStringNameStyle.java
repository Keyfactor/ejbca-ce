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

import com.keyfactor.util.CeSecoreNameStyle;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500NameStyle;

/**
 * Like CeSecoreNameStyle, but uses PrintableStrings to encode most attributes
 * (the default encoding is UTF-8)
 */
public class PrintableStringNameStyle extends CeSecoreNameStyle {

    public static final X500NameStyle INSTANCE = new PrintableStringNameStyle();
    
    protected PrintableStringNameStyle() { }
    
    /**
     * return true if the passed in String can be represented without
     * loss as a PrintableString, false otherwise.
     */
    private boolean canBePrintable(String  str) {
        return DERPrintableString.isPrintableString(str);
    }

    @Override
    public ASN1Encodable stringToValue(ASN1ObjectIdentifier oid, String value) {
        // Let super classes encode value first, then check if we need to change it
        // THis is better than copying, and keeping updated, from super class
        ASN1Encodable asn1Value = super.stringToValue(oid, value);
        if (asn1Value instanceof DERUTF8String) {
            if (canBePrintable(value)) {
                return new DERPrintableString(value);
            }   
        }
        return asn1Value;
    }
    
}
