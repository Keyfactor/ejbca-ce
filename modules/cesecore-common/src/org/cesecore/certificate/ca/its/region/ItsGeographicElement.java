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

import java.io.Serializable;
import java.util.List;

import org.bouncycastle.oer.its.ieee1609dot2.basetypes.GeographicRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.IdentifiedRegion;

public interface ItsGeographicElement extends Serializable {
    
    public String getFormatHint();
    
    // to enforce override of toString
    public String toStringFormat();
    
    public ItsGeographicElement fromString(String formattedString);
    
    public GeographicRegion getGeographicRegion();
    
    public IdentifiedRegion getIdentifiedRegion();
    
    public void validateArgs();
    
    public List<String> getGuiDescription();
    
    /**
     * To be implemented for validation purpose of requestedRegion in enrollment request
     * and current region instance of CA.
     * 
     * may use any(any/all) logic while validating against sequence. 
     * @return
     */
    public boolean isSubregion(ItsGeographicElement requestedRegion);
    
}