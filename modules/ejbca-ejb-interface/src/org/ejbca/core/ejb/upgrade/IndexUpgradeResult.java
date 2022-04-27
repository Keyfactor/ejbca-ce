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
package org.ejbca.core.ejb.upgrade;

/**
 * Status of an upgrade of a database index.
 */
public enum IndexUpgradeResult {
    /** Index existed and was successfully upgraded */
    OK_UPDATED,
    /** Index did not exist (deletion failed) */
    NO_EXISTNG_INDEX,
    /** An error occurred while creating the new index */
    ERROR
}
