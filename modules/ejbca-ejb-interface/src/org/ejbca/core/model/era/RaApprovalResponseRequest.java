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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Used for approving requests from RaManageRequestBean
 * @version $Id$
 */
public class RaApprovalResponseRequest implements Serializable {

    public static enum Action {
        SAVE,
        APPROVE,
        REJECT;
    }
    
    public final static class MetadataResponse implements Serializable {
        private static final long serialVersionUID = 1L;
        private final int metadataId;
        private final String optionValue;
        private final String optionNote;
        
        public MetadataResponse(final int metadataId, final String optionValue, final String optionNote) {
            this.metadataId = metadataId;
            this.optionValue = optionValue;
            this.optionNote = optionNote;
        }
        
        public int getMetadataId() { return metadataId; }
        public String getOptionValue() { return optionValue; }
        public String getOptionNote() { return optionNote; }
    }
    
    private static final long serialVersionUID = 1L;
    /** id of approval */
    private final int id;
    private final int stepId;
    private final String comment;
    private final List<MetadataResponse> metadataList = new ArrayList<>();
    private final Action action;
    
    public RaApprovalResponseRequest(final int id, final int stepId, final String comment, final Action action) {
        this.id = id;
        this.stepId = stepId;
        this.comment = comment;
        this.action = action;
    }
    
    public void addMetadata(final int metadataId, final String optionValue, final String optionNote) {
        metadataList.add(new MetadataResponse(metadataId, optionValue, optionNote));
    }

    public int getId() {
        return id;
    }

    public int getStepId() {
        return stepId;
    }

    public String getComment() {
        return comment;
    }
    
    public List<MetadataResponse> getMetadataList() {
        return metadataList;
    }
    
    public Action getAction() {
        return action;
    }

}
