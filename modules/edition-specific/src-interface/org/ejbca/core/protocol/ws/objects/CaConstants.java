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
package org.ejbca.core.protocol.ws.objects;

import org.cesecore.certificates.ca.catoken.CAToken;

public class CaConstants {

    /**
     * The policy ID can be 'null' if no Certificate Policy extension should be present, or\nobjectID as '2.5.29.32.0' 
     * or objectID and cpsurl as '2.5.29.32.0 http://foo.bar.com/mycps.txt'. You can add multiple policies such as 
     * '2.5.29.32.0 http://foo.bar.com/mycps.txt 1.1.1.1.1 http://foo.bar.com/111cps.txt'.
     */
    public static final String POLICYID = "policyid";
    
    // Key Aliases
    public static final String SOFTPRIVATESIGNKEYALIAS = CAToken.SOFTPRIVATESIGNKEYALIAS;
    public static final String SOFTPREVIOUSPRIVATESIGNKEYALIAS = CAToken.SOFTPREVIOUSPRIVATESIGNKEYALIAS;
    public static final String SOFTNEXTPRIVATESIGNKEYALIAS = CAToken.SOFTNEXTPRIVATESIGNKEYALIAS;
    public static final String SOFTPRIVATEDECKEYALIAS = CAToken.SOFTPRIVATEDECKEYALIAS;
    
}
