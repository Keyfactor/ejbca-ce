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

import javax.ejb.Remote;

/**
 * Remote interface for TableProtectSession.
 * 
 * FIXME: The name of this class is temporarily in conflict with its ejb2 predecessor.
 * Remove ejb3 postfix after the xdoclet-class has ceased to exist.
 */
@Remote
public interface TableProtectSessionRemoteejb3 {
    /**
     * Store a protection entry in an external, remote database.
     * 
     * @param Protectable
     *            the object beeing protected
     */
    public void protectExternal(org.ejbca.core.model.protect.Protectable entry, java.lang.String dataSource) throws java.rmi.RemoteException;

    /**
     * Store a protection entry.
     * 
     * @param admin
     *            the administrator performing the event.
     * @param Protectable
     *            the object beeing protected
     */
    public void protect(org.ejbca.core.model.protect.Protectable entry) throws java.rmi.RemoteException;

    /**
     * Verifies a protection entry.
     * 
     * @param admin
     *            the administrator performing the event.
     * @param Protectable
     *            the object beeing verified
     * @return TableVerifyResult, never null
     */
    public org.ejbca.core.model.protect.TableVerifyResult verify(org.ejbca.core.model.protect.Protectable entry) throws java.rmi.RemoteException;
}
