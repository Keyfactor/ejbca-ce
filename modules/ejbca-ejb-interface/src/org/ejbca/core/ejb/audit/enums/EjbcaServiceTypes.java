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
package org.ejbca.core.ejb.audit.enums;

import org.cesecore.audit.enums.ServiceType;

/**
 * @version $Id$
 */
public enum EjbcaServiceTypes implements ServiceType {
    /** Enterprise JavaBeans Certificate Authority */
    EJBCA;
    
    @Override
    public boolean equals(ServiceType value) {
        if(value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }
}
