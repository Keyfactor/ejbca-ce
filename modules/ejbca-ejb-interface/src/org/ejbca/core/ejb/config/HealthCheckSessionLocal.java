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
package org.ejbca.core.ejb.config;

import javax.ejb.Local;

/**
 * @version $Id$
 */
@Local
public interface HealthCheckSessionLocal extends HealthCheckSession {

    /**
     * Used by health-check. Validate database connection.
     * @return an error message or an empty String if all are ok.
     */
    String getDatabaseStatus();

}
