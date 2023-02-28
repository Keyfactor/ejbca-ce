/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.crypto.algorithm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Configuration cache for key and algorithm related values.
 */
public enum AlgorithmConfigurationCache {
    INSTANCE; 
    
    private boolean gost3410Enabled;
    private boolean dstu4145Enabled;
    
    private List<String> configurationDefinedAlgorithms;
    private Map<String, String> configurationDefinedAlgorithmTitles;

    private AlgorithmConfigurationCache() {
        gost3410Enabled = false;
        dstu4145Enabled = false;
        configurationDefinedAlgorithms = new ArrayList<>();
        configurationDefinedAlgorithmTitles = new HashMap<>();
       
    }
    
    public boolean isGost3410Enabled() {
        return gost3410Enabled;
    }
    
    public void setGost3410Enabled(boolean gost3410Enabled) {
        this.gost3410Enabled = gost3410Enabled;
    }

    public boolean isDstu4145Enabled() {
        return dstu4145Enabled;
    }

    public void setDstu4145Enabled(boolean dstu4145Enabled) {
        this.dstu4145Enabled = dstu4145Enabled;
    }

    public List<String> getConfigurationDefinedAlgorithms() {
        return configurationDefinedAlgorithms;
    }

    public void setConfigurationDefinedAlgorithms(List<String> configurationDefinedAlgorithms) {
        this.configurationDefinedAlgorithms = configurationDefinedAlgorithms;
    }

    public String getConfigurationDefinedAlgorithmTitle(final String algorithm) {
        return configurationDefinedAlgorithmTitles.get(algorithm);
    }

    public void addConfigurationDefinedAlgorithmTitle(final String algorithm, final String title) {
        configurationDefinedAlgorithmTitles.put(algorithm, title);
    }

}
