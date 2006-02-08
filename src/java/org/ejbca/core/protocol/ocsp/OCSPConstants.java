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

package org.ejbca.core.protocol.ocsp;

/**
 * 
 * @author tomasg
 * @version $Id: OCSPConstants.java,v 1.2 2006-02-08 07:31:47 anatom Exp $
 */
public class OCSPConstants {

    /** Constants capturing the OCSP response status 
     * 
     */
    public static final int OCSP_GOOD = 1;
    public static final int OCSP_REVOKED = 2;
    public static final int OCSP_UNKNOWN = 3;

}
