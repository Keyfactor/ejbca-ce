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

import javax.ejb.Remote;

/**
 * Remote interface for the SecurityEventsLogger
 * 
 * Based on CESeCore version:
 *      SecurityEventsLoggerSessionRemote.java 167 2011-01-27 09:11:21Z tomas
 * 
 * @version $Id$
 *
 */
@Remote
public interface SecurityEventsLoggerSessionRemote extends SecurityEventsLoggerSession {

}
