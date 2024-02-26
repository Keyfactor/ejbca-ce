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
package org.ejbca.core.ejb.ocsp;

/**
 * Denotes the possible choices for response validity time. The default is for the nextUpdate value to be polled from the configuration, 
 * but in a specific eIDAS usecase this time can be set to practical infinity. The latter is a MASSIVE FOOT GUN and should be used with caution.
 */
public enum PresignResponseValidity {
    UNLIMITED_VALIDITY_EIDAS, CONFIGURATION_BASED;
}
