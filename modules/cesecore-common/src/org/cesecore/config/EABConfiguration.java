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

import org.apache.log4j.Logger;
import org.cesecore.configuration.ConfigurationBase;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class EABConfiguration extends ConfigurationBase implements Serializable {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(EABConfiguration.class);
    private static final long serialVersionUID = 1L;
    public static final String EAB_CONFIGURATION_ID = "EAB";
    // Default OAuth Keys
    private static final LinkedHashMap<String, Set<String>> EAB_MAP_DEFAULT = new LinkedHashMap<>();

    private static final   String EAB_MAP          = "eabmap";

    {
        EAB_MAP_DEFAULT.put("Cats", new HashSet<>(Arrays.asList("Abyssinian", "Bengal", "Birman", "British Shorthair", "Cheshire", "Cornish Rex", "Devon Rex", "Egyptian Mau", "Himalayan", "Korat", "Maine Coon","Munchkin", "Nebelung", "Norwegian Forest Cat", "Ocicat", "Persian", "Ragamuffin", "Russian Blue", "Scottish Fold", "Siamese", "Siberian", "Singapura", "Sphynx", "Tonkinese", "Turkish Angora")));
        EAB_MAP_DEFAULT.put("Dogs", new HashSet<>(Arrays.asList("Afghan Hound", "Alaskan Malamute", "American Bulldog", "American Pit Bull Terrier", "Azawakh", "Bassador", "Basset Hound", "Beagle", "Belgian Sheepdog", "Black Russian Terrier", "Bloodhound", "Bolognese", "Border Collie", "Borzoi", "Boxer", "Bulldog", "Cane Corso", "Caucasian Shepherd Dog", "Chihuahua", "Collie", "Dachshund", "Dalmatian", "Doberman Pinscher", "English Setter")));
        EAB_MAP_DEFAULT.put("Flowers",new HashSet<>(Arrays.asList("Rose", "Lily", "Tulip", "Orchid")));
        EAB_MAP_DEFAULT.put("Trees", new HashSet<>(Arrays.asList("Ash", "Birch", "Cherry", "Chestnut", " Larch", "Maple", "Oak", "Pine")));
    }

    public Map<String, Set<String>> getEABMap() {
        final Map<String, Set<String>>  ret = (Map<String, Set<String>> )data.get(EAB_MAP);
        return (ret == null ? (Map<String, Set<String>>) EAB_MAP_DEFAULT.clone() : new LinkedHashMap<>(ret));
    }

    /** Sets the available OAuth keys */
    public void setOauthKeys(Map<String, Set<String>> eabMap) {
        data.put(EAB_MAP, eabMap);
    }

    @Override
    public void upgrade() {

    }

    @Override
    public String getConfigurationId() {
        return EAB_CONFIGURATION_ID;
    }
}
