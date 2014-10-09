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

package org.cesecore.configuration;

import org.cesecore.internal.UpgradeableDataHashMap;

public abstract class ConfigurationBase extends UpgradeableDataHashMap {

    private static final long serialVersionUID = 4886872276324915327L;

    public static final float LATEST_VERSION = 3f;
        
    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public abstract void upgrade();

}
