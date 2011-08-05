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
package org.cesecore.certificates.ca;

/**
 * Constants for CAs.
 *
 * Based on EJBCA version: SecConst.java 11245 2011-01-24 00:56:57Z dcarella
 * 
 * @version $Id: CAConstants.java 349 2011-02-25 16:06:32Z tomas $
 */
public final class CAConstants {
    
    /**
     * Prevents creation of new CAConstants
     */
    private CAConstants() {
    }

    /**
     * Constants used in the SignSessionBean indicating the userdata defined CA should be used.
     */
    public static final int CAID_USEUSERDEFINED = 0;
    
    /** Constants used to indicate status of a CA. */
    public static final int CA_ACTIVE = 1;
    public static final int CA_WAITING_CERTIFICATE_RESPONSE = 2;
    public static final int CA_EXPIRED = 3;
    public static final int CA_REVOKED = 4;
    public static final int CA_OFFLINE = 5;
    public static final int CA_EXTERNAL = 6;    

    /** Used in profiles and service workers to make the catch all every CA instead of listing individual CAs when operating on them */
    public static final int ALLCAS = 1;

}