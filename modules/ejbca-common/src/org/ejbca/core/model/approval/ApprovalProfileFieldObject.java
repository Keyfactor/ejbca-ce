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
package org.ejbca.core.model.approval;

import java.io.Serializable;
import java.util.List;

public class ApprovalProfileFieldObject implements Serializable {

    private static final long serialVersionUID = 8652607031017119847L;
    
    public static final int METADATATYPE_CHECKBOX = 1;
    public static final int METADATATYPE_RADIOBUTTON = 2;
    public static final int METADATATYPE_TEXTBOX = 3;
    
    private String keyObject;
    private String description;
    private List<String> metaData;
    private int metaDataType;
    
    public ApprovalProfileFieldObject(String mainObject, String desc, List<String> metaData, int metadatatype) {
        this.keyObject = mainObject;
        this.description = desc;
        this.metaData = metaData;
        this.metaDataType = metadatatype;
    }
    
    public String getKeyObject() {
        return keyObject;
    }
    
    public String getDescription() {
        return description;
    }
    
    public List<String> getMetaData() {
        return metaData;
    }
    
    public int getMetaDataType() {
        return metaDataType;
    }
} 
