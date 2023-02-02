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
package org.ejbca.core.ejb.ra;

import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Wraps an existing end entity. Used for change detection.
 *
 * @see EndEntityManagementSessionBean#classifyUserDataChanges
 */
public final class OriginalEndEntity {

    private final EndEntityInformation endEntity;

    /** Pass null if (and only if) the end entity does not exist */
    public OriginalEndEntity(final EndEntityInformation endEntity) {
        this.endEntity = endEntity;
    }

    public EndEntityInformation getEndEntity() {
        return endEntity;
    }

    public boolean isExisting() {
        return endEntity != null;
    }

}
