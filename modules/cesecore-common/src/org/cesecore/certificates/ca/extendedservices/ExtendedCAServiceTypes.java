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

package org.cesecore.certificates.ca.extendedservices;

/**
 * 
 *
 */

public class ExtendedCAServiceTypes {

    @Deprecated //Removed in EJBCA 6.0.0, and retained to support migration. Remove once support for upgrading from 4.0.x is dropped. 
	public static final int TYPE_OCSPEXTENDEDSERVICE   = 1; 	
    // Number 2 was XKMS, do not re-use this as it might cause interoperability/upgrade issues from older installations that had it
    /**
     * @deprecated Since EJBCA 8.0.0, where the CMS extended service was removed. 
     */
    @Deprecated
	public static final int TYPE_CMSEXTENDEDSERVICE = 3;
	
	@Deprecated //Removed in EJBCA 7.1.0, and retained to support migration. Remove once support for upgrading from 7.0.x is dropped.
	public static final int TYPE_HARDTOKENENCEXTENDEDSERVICE = 4;
	
	public static final int TYPE_KEYRECOVERYEXTENDEDSERVICE = 5;

}
