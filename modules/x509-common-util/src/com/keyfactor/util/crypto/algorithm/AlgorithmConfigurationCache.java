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
    
    private String ecDsaImplicitlyCaQ;
    private String ecDsaImplicitlyCaA;
    private String ecDsaImplicitlyCaB;
    private String ecDsaImplicitlyCaG;
    private String ecDsaImplicitlyCaN;
    
    private List<String> configurationDefinedAlgorithms;
    private Map<String, String> configurationDefinedAlgorithmTitles;

    private AlgorithmConfigurationCache() {
        gost3410Enabled = false;
        dstu4145Enabled = false;
        configurationDefinedAlgorithms = new ArrayList<>();
        configurationDefinedAlgorithmTitles = new HashMap<>();
        
        //Set defaults
        ecDsaImplicitlyCaQ = "883423532389192164791648750360308885314476597252960362792450860609699839";
        ecDsaImplicitlyCaA = "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc";
        ecDsaImplicitlyCaB = "6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a";
        ecDsaImplicitlyCaG = "020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf";
        ecDsaImplicitlyCaN = "883423532389192164791648750360308884807550341691627752275345424702807307";
        
       
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

    public String getEcDsaImplicitlyCaQ() {
        return ecDsaImplicitlyCaQ;
    }

    public void setEcDsaImplicitlyCaQ(String ecDsaImplicitlyCaQ) {
        this.ecDsaImplicitlyCaQ = ecDsaImplicitlyCaQ;
    }

    public String getEcDsaImplicitlyCaA() {
        return ecDsaImplicitlyCaA;
    }

    public void setEcDsaImplicitlyCaA(String ecDsaImplicitlyCaA) {
        this.ecDsaImplicitlyCaA = ecDsaImplicitlyCaA;
    }

    public String getEcDsaImplicitlyCaB() {
        return ecDsaImplicitlyCaB;
    }

    public void setEcDsaImplicitlyCaB(String ecDsaImplicitlyCaB) {
        this.ecDsaImplicitlyCaB = ecDsaImplicitlyCaB;
    }

    public String getEcDsaImplicitlyCaG() {
        return ecDsaImplicitlyCaG;
    }

    public void setEcDsaImplicitlyCaG(String ecDsaImplicitlyCaG) {
        this.ecDsaImplicitlyCaG = ecDsaImplicitlyCaG;
    }

    public String getEcDsaImplicitlyCaN() {
        return ecDsaImplicitlyCaN;
    }

    public void setEcDsaImplicitlyCaN(String ecDsaImplicitlyCaN) {
        this.ecDsaImplicitlyCaN = ecDsaImplicitlyCaN;
    }

}
