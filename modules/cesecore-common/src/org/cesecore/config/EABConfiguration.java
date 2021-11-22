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

package org.cesecore.config;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.cesecore.configuration.ConfigurationBase;

public class EABConfiguration extends ConfigurationBase implements Serializable {

    /** Class logger. */
    private static final long serialVersionUID = 1L;
    public static final String EAB_CONFIGURATION_ID = "EAB";
    private static final LinkedHashMap<String, Set<String>> EAB_MAP_DEFAULT = new LinkedHashMap<>();

    private static final   String EAB_MAP          = "eabmap";
    private static final   String FILE_HASH        = "filehash";

    @SuppressWarnings("unchecked")
    public Map<String, Set<String>> getEABMap() {
        final Map<String, Set<String>> ret = (Map<String, Set<String>>) data.get(EAB_MAP);
        return (ret == null ? (Map<String, Set<String>>) EAB_MAP_DEFAULT.clone() : new LinkedHashMap<>(ret));
    }

    /** Sets the available OAuth keys */
    public void setEabConfigMap(Map<String, Set<String>> eabMap) {
        data.put(EAB_MAP, eabMap);
    }
    
    public String getFileHash() {
        return (String) data.get(FILE_HASH);
    }

    /** Sets the SHA-256 hash of the uploaded CSV file */
    public void setFileHash(String fileHash) {
        data.put(FILE_HASH, fileHash);
    }

    @Override
    public void upgrade() {

    }

    @Override
    public String getConfigurationId() {
        return EAB_CONFIGURATION_ID;
    }
}
