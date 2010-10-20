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

package org.ejbca.core.protocol.cmp;

import java.io.IOException;

import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.IResponseMessage;

/**
 * @version $Id$
 */
public interface CmpMessageDispatcherSession {
	public IResponseMessage dispatch(Admin admin, byte[] derObject) throws IOException;
}
