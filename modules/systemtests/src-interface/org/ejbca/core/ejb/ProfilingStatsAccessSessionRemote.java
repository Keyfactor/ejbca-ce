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
package org.ejbca.core.ejb;

import java.util.List;

import javax.ejb.Remote;

/**
 * @see org.ejbca.core.ProfilingStatsAccessSessionBean
 * 
 * @version $Id$
 */
@Remote
public interface ProfilingStatsAccessSessionRemote {
    
    /** @see org.ejbca.core.ejb.ProfilingStats#getEjbInvocationStats() */
    public List<ProfilingStat> getEjbInvocationStats();
}
