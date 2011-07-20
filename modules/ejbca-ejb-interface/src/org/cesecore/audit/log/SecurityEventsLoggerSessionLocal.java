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
package org.cesecore.audit.log;

import javax.ejb.Local;

/**
 * Local interface for the SecurityEventsLogger
 * 
 * Based on CESeCore version:
 *      SecurityEventsLoggerSessionLocal.java 900 2011-06-21 16:33:28Z johane
 * 
 * @version $Id$
 */
@Local
public interface SecurityEventsLoggerSessionLocal extends SecurityEventsLoggerSession {
}
