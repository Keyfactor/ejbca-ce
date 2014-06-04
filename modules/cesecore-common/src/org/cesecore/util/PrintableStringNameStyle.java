/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

/**
 * Like CeSecoreNameStyle, but uses PrintableStrings to encode most attributes
 * (the default encoding is UTF-8)
 * 
 * @version $Id$
 */
public class PrintableStringNameStyle extends CeSecoreNameStyle {

    public static final X500NameStyle INSTANCE = new PrintableStringNameStyle();
    
    protected PrintableStringNameStyle() { }
    
    /**
     * return true if the passed in String can be represented without
     * loss as a PrintableString, false otherwise.
     */
    private boolean canBePrintable(
        String  str)
    {
        return DERPrintableString.isPrintableString(str);
    }

    @Override
    public ASN1Encodable stringToValue(ASN1ObjectIdentifier oid, String value)
    {
        if (value.length() != 0 && value.charAt(0) == '#')
        {
            try
            {
                return IETFUtils.valueFromHexString(value, 1);
            }
            catch (IOException e)
            {
                throw new RuntimeException("can't recode value for oid " + oid.getId());
            }
        }
        else if (value.length() != 0 && value.charAt(0) == '\\')
        {
            value = value.substring(1);
        }
        else if (oid.equals(CeSecoreNameStyle.EmailAddress) || oid.equals(CeSecoreNameStyle.DC))
        {
            return new DERIA5String(value);
        }
        else if (canBePrintable(value))  
        {
            return new DERPrintableString(value);
        }

        return new DERUTF8String(value);
    }
    
}
