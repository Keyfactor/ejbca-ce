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
package org.ejbca.core.ejb.signer.impl;

import org.ejbca.core.ejb.signer.SignerMappingBase;

/**
 * Holder of "external" OCSP signer mapping relevant properties.
 * 
 * @version $Id$
 */
public class OcspSignerMapping extends SignerMappingBase {
    
    private static final long serialVersionUID = 1L;

    public static final String PROPERTY_NON_EXISTING_GOOD = "nonExistingGood";
    
    @Override
    public String getSignerMappingAlias() {
        return "OcspSignerMapping";
    }
    
    @Override
    public float getLatestVersion() {
        return Long.valueOf(serialVersionUID).floatValue();
    }

    @Override
    protected void upgrade(float latestVersion, float currentVersion) {
        // Nothing to do
    }

    public boolean getNonExistingGood() {
        return Boolean.valueOf(getData(PROPERTY_NON_EXISTING_GOOD, Boolean.FALSE.toString())).booleanValue();
    }
    public void setNonExistingGood(boolean nonExistingGood) {
        putData(PROPERTY_NON_EXISTING_GOOD, Boolean.valueOf(nonExistingGood).toString());
    }
}
