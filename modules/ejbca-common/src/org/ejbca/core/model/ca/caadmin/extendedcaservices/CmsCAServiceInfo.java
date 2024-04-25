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
package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;

/**
 * Kept only for backward compatibility with old CAs (older than 8.0),
 * when this node is running as a peer-connected RA.
 *
 * @deprecated CMS support removed in 8.0
 */
@Deprecated
public class CmsCAServiceInfo extends ExtendedCAServiceInfo {

    private static final long serialVersionUID = 7556251008892332034L;

    public CmsCAServiceInfo(int status) {
        super(status);
        throw new UnsupportedOperationException("Internal error. A part of EJBCA attempted to use legacy CMS functionality");
    }

    @Override
    public String getImplClass() {
        throw new UnsupportedOperationException("Internal error. A part of EJBCA attempted to use legacy CMS functionality");
    }

    @Override
    public int getType() {
        throw new UnsupportedOperationException("Internal error. A part of EJBCA attempted to use legacy CMS functionality");
    }

}
