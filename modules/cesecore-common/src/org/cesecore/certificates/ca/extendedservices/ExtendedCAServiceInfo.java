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
package org.cesecore.certificates.ca.extendedservices;

import java.io.Serializable;

/**
 * Should be inherited by all ExtendedCAServiceInfo Value objects. These classes are used to retrieve general information about the service and also
 * used to send parameters to the service when creating it.
 * 
 * @version $Id$
 */
public abstract class ExtendedCAServiceInfo implements Serializable {

    private static final long serialVersionUID = 9064707908058917449L;

    /**
     * Constants indicating the status of the service.
     */
    public static final int STATUS_INACTIVE = 1;
    public static final int STATUS_ACTIVE = 2;

    private int status = STATUS_INACTIVE;

    public static final String IMPLEMENTATIONCLASS = "IMPLCLASS";

    public ExtendedCAServiceInfo(int status) {
        this.status = status;
    }

    public int getStatus() {
        return this.status;
    }

    public void setStatus(final int status) {
        this.status = status;
    }

    /** @return a unique type identifier, such as ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE etc */
    public abstract int getType();

    /**
     * The extended CA service implementation will be created using reflection.
     * 
     * @return a class name implementing the extended CA service
     */
    public abstract String getImplClass();

}
