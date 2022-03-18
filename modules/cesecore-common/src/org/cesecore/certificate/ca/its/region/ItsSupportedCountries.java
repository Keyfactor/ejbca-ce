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
package org.cesecore.certificate.ca.its.region;

import java.util.ArrayList;
import java.util.List;

public enum ItsSupportedCountries {
    // https://unstats.un.org/unsd/methodology/m49/
    AUSTRIA("Austria", 040), 
    BELGIUM("Belgium", 056), 
    BULGARIA("Bulgaria", 100), 
    CROATIA("Croatia", 191), 
    CYPRUS("Cyprus", 196), 
    CZECH_REPUBLIC("Czech Republic", 203), 
    DENMARK("Denmark", 208), 
    ESTONIA("Estonia", 233), 
    FINLAND("Finland", 246), 
    FRANCE("France", 250), 
    GERMANY("Germany", 276), 
    GREECE("Greece", 300), 
    HUNGARY("Hungary", 348), 
    IRELAND("Ireland", 372), 
    ITALY("Italy", 380), 
    LATVIA("Latvia", 428), 
    LITHUNIA("Lithuania", 440), 
    LUXEMBOURG("Luxembourg", 442), 
    MALTA("Malta", 470), 
    NETHERLANDS("Netherlands", 528), 
    POLAND("Poland", 616), 
    PORTUGAL("Portugal", 620), 
    ROMANIA("Romania", 642), 
    SLOVAKIA("Slovakia", 703), 
    SLOVENIA("Slovenia", 705), 
    SPAIN("Spain", 724), 
    SWEDEN("Sweden", 752),
    WHOLE_EUROPE("-Europe", ItsGeographicRegion.IDENTIFIED_REGION_EUROPE);

    private String displayName;
    private int m49Code;
    
    ItsSupportedCountries(String displayName, int m49Code) {
        this.setDisplayName(displayName);
        this.setM49Code(m49Code);
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public int getM49Code() {
        return m49Code;
    }

    public void setM49Code(int m49Code) {
        this.m49Code = m49Code;
    }
    
    public static List<String> getSupportedCountryNames() {
        List<String> names = new ArrayList<>();
        for(ItsSupportedCountries sc : values()){
            names.add(sc.getDisplayName());
        }
        names.sort(null);
        return names;
    }

    public static ItsSupportedCountries fromDisplayName(String country) {
        for(ItsSupportedCountries sc : values()){
            if(sc.getDisplayName().equalsIgnoreCase(country)){
                return sc;
            }
        }
        throw new IllegalArgumentException("Invalid country name: " + country);
    }
    
    public static ItsSupportedCountries fromCountryCode(int countryCode) {
        for(ItsSupportedCountries sc : values()){
            if(sc.getM49Code()==countryCode){
                return sc;
            }
        }
        throw new IllegalArgumentException("Invalid country M49 code: " + countryCode);
    }
}