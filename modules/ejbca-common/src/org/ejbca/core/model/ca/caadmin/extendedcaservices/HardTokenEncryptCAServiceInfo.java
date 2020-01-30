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
package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.io.Serializable;

import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;

/**
 * Deprecated class. Kept for backwards compatibility with 6.15 or older CA peer systems, which send this class in serialized data, to the RAs.
 * @version $Id$
 * @deprecated Since 7.0 (was removed in 7.0 until 7.4.0)
 */
@Deprecated
public class HardTokenEncryptCAServiceInfo extends ExtendedCAServiceInfo implements Serializable {

    private static final long serialVersionUID = -6186500870565287684L;

    /** Dummy constructor. Not used. Deserialization uses the default constructor */
    public HardTokenEncryptCAServiceInfo(int status) {
        super(status);
        throw new UnsupportedOperationException("Internal error. A part of EJBCA attempted to use legacy hard token functionality");
    }

    @Override
    public String getImplClass() {
        throw new UnsupportedOperationException("Internal error. A part of EJBCA attempted to use legacy hard token functionality");
    }

    @Override
    public int getType() {
        throw new UnsupportedOperationException("Internal error. A part of EJBCA attempted to use legacy hard token functionality");
    }

}
