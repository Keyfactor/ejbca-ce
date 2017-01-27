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
package org.cesecore.authorization.control;

import javax.ejb.Local;

/**
 * Local interface for AccessControl
 * 
 * @See {@link AccessControlSession}
 * 
 * @version $Id$
 * 
 */
@Deprecated
@Local
public interface AccessControlSessionLocal extends AccessControlSession {
   
}
