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
package org.cesecore.certificates.util.dn;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.ejbca.util.EjbcaNameStyle;

/**
 * A converter for X509 DN entries that uses PrintableString where possible.
 * Default encoding is UTF-8, so this one is used when the default encoding is not desired.
 * 
 * Based on EJBCA version: 
 *      PrintableStringEntryConverter.java 8373 2009-11-30 14:07:00Z jeklund
 * Based on CESeCore version: 
 *      PrintableStringEntryConverter.java 146 2011-01-25 11:59:11Z tomas
 * 
 * @version $Id$
 */
public class PrintableStringEntryConverter
    extends X509NameEntryConverter
{
	
	/**
     * return true if the passed in String can be represented without
     * loss as a UTF8String, false otherwise.
     */
    private boolean canBeUTF8(
        String  str)
    {
        for (int i = str.length() - 1; i >= 0; i--)
        {
            if (str.charAt(i) > 0x00ff)
            {
                return false;
            }
        }

        return true;
    }
    
    /**
     * Apply default coversion for the given value depending on the oid
     * and the character range of the value.
     * 
     * @param oid the object identifier for the DN entry
     * @param value the value associated with it
     * @return the ASN.1 equivalent for the string value.
     */
    public ASN1Primitive getConvertedValue(
        ASN1ObjectIdentifier  oid,
        String               value)
    {
        if (value.length() != 0 && value.charAt(0) == '#')
        {
            try
            {
                return convertHexEncoded(value, 1);
            }
            catch (IOException e)
            {
                throw new RuntimeException("can't recode value for oid " + oid.getId());
            }
        }
        else if (oid.equals(EjbcaNameStyle.EmailAddress) || oid.equals(EjbcaNameStyle.DC))
        {
            return new DERIA5String(value);
        }
        else if (canBePrintable(value))  
        {
            return new DERPrintableString(value);
        }
        else if (canBeUTF8(value))
        {
            return new DERUTF8String(value);
        }

        return new DERBMPString(value);
    }
}
