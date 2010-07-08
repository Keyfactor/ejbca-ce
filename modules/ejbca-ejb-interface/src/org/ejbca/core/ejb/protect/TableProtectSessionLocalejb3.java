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
package org.ejbca.core.ejb.protect;

import javax.ejb.Local;

/**
 * Local interface for TableProtectSession.
 * 
 * FIXME: The name of this class is temporarily in conflict with its ejb2
 * predecessor. Remove ejb3 postfix after the xdoclet-class has ceased to exist.
 */
@Local
public interface TableProtectSessionLocalejb3 extends TableProtectSession {
   
}
