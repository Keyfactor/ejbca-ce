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
package org.ejbca.core.model.hardtoken;


/**
 * @version $Id$
 */
public interface HardTokenConstants {
    
    public static final int REQUESTTYPE_PKCS10_REQUEST   = 1;
    public static final int REQUESTTYPE_KEYSTORE_REQUEST = 2;
    
    public static final int RESPONSETYPE_CERTIFICATE_RESPONSE   = 1;
    public static final int RESPONSETYPE_KEYSTORE_RESPONSE = 2;
    
    public static final String TOKENTYPE_PKCS12 = "PKCS12";
}
