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

//@javax.xml.bind.annotation.XmlSchema(namespace = "http://www.w3.org/2002/03/xkms#", elementFormDefault = javax.xml.bind.annotation.XmlNsForm.QUALIFIED)
@javax.xml.bind.annotation.XmlSchema(
        namespace = "http://www.w3.org/2002/03/xkms#", 
        xmlns={
                @javax.xml.bind.annotation.XmlNs( prefix = "xsi", namespaceURI="http://www.w3.org/2001/XMLSchema-instance"),
                @javax.xml.bind.annotation.XmlNs(prefix="ds", namespaceURI="http://www.w3.org/2000/09/xmldsig#"),
                @javax.xml.bind.annotation.XmlNs(prefix="xenc", namespaceURI="http://www.w3.org/2001/04/xmlenc#"),
                @javax.xml.bind.annotation.XmlNs(prefix="", namespaceURI="http://www.w3.org/2002/03/xkms#")
              }, 
        elementFormDefault = javax.xml.bind.annotation.XmlNsForm.QUALIFIED
)
package org.ejbca.core.protocol.xkms;
