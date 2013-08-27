package org.ejbca.config;

import org.cesecore.internal.UpgradeableDataHashMap;

public class Configuration extends UpgradeableDataHashMap {

    private static final long serialVersionUID = 4886872276324915327L;

    public static final float LATEST_VERSION = 3f;
    
    public static final String GlobalConfigID = "0";
    public static final String CMPConfigID = "1";
    
    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public void upgrade() {
        // Expected to be overriden
    }

}
