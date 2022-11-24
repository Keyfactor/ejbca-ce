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
package org.cesecore.certificates.ca.kfenroll;

import org.cesecore.certificates.ca.CA;

/**
 * General interface for Proxy CA
 * (available in specific editions of EJBCA only)
 */
public interface ProxyCa extends CA {

    public static final String CA_TYPE = "KeyfactorEnrollmentProxyCA";

}
