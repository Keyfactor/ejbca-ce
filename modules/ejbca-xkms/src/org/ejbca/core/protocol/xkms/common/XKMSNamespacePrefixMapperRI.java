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

package org.ejbca.core.protocol.xkms.common;

/**
 * Class that implement the mappings of specific for 
 * XML signatures, encryption and xkms.
 * 
 * This is exactly the same content as XKMSNamespacePrefixMapper
 * 
 * @version $Id$
 */
public class XKMSNamespacePrefixMapperRI extends com.sun.xml.bind.marshaller.NamespacePrefixMapper {

	@Override
	public String getPreferredPrefix(String namespaceUri, String suggestion, boolean requirePrefix) {
        if( namespaceUri.equals("http://www.w3.org/2001/XMLSchema-instance") ){
            return "xsi";
	    }
		if(namespaceUri.equals("http://www.w3.org/2000/09/xmldsig#")){
			return "ds";
		}
		if(namespaceUri.equals("http://www.w3.org/2001/04/xmlenc#")){
			return "xenc";
		}
		if(namespaceUri.equals("http://www.w3.org/2002/03/xkms#")){
			return "";
		}
		return suggestion;
	}

}
