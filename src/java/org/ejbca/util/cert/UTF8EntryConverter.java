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

package org.ejbca.util.cert;

import java.io.IOException;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;

/**
 * A converter for X509 DN entries that always use UTF8String if possible,
 * used the create Subject DNs in Bouncycastle. 
 * Basically copied from BC's file X509DefaultEntryConverter.
 * 
 * @version $Id: UTF8EntryConverter.java,v 1.1 2006-06-06 15:31:09 anatom Exp $
 */
public class UTF8EntryConverter extends X509NameEntryConverter
{
	/**
	 * Apply default coversion for the given value depending on the oid
	 * and the character range of the value.
	 * 
	 * @param oid the object identifier for the DN entry
	 * @param value the value associated with it
	 * @return the ASN.1 equivalent for the string value.
	 */
	public DERObject getConvertedValue(
			DERObjectIdentifier  oid,
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
		else if (oid.equals(X509Name.EmailAddress))
		{
			return new DERIA5String(value);
		}
		return new DERUTF8String(value);
	}
}
