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
package org.ejbca.core.model.era;

import org.cesecore.keys.keyimport.KeyImportFailure;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * RaResponse for Key Migration.
 */
public class RaKeyImportResponseV2 implements Serializable {

    private static final long serialVersionUID = 1L;

    private List<KeyImportFailure> failedKeys = new ArrayList<>();

    public List<KeyImportFailure> getFailedKeys() {
        return failedKeys;
    }

    public void setFailedKeys(List<KeyImportFailure> failedKeys) {
        this.failedKeys = failedKeys;
    }
}
