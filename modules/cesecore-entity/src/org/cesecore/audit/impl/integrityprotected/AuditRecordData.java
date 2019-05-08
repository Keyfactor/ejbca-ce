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
package org.cesecore.audit.impl.integrityprotected;

import java.io.Serializable;
import java.util.Map;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.commons.lang.StringUtils;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypeHolder;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ModuleTypeHolder;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.enums.ServiceTypeHolder;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.CertTools;
import org.cesecore.util.GUIDGenerator;
import org.cesecore.util.XmlSerializer;

/**
 * This class represents an audit log record.
 * 
 * The following index is recommended as a minimum:
 * create unique index auditrecorddata_idx1 on AuditRecordData (nodeId,timeStamp,sequenceNumber);
 * 
 * @version $Id$
 */
@Entity
@Table(name="AuditRecordData")
public class AuditRecordData extends ProtectedData implements Serializable, AuditLogEntry {

    private static final long serialVersionUID = 3998646190932834045L;
   
    private String pk;
    private String nodeId;
    private Long sequenceNumber;
    private Long timeStamp;
    private String eventType;
    private String eventStatus;
    private String authToken;
    private String service;
    private String module;
    private String customId;
    private String searchDetail1;
    private String searchDetail2;
    private String additionalDetails;
    private int rowVersion = 0;
    private String rowProtection;

    public AuditRecordData() {}
    
    public AuditRecordData(final String nodeId, final Long sequenceNumber, final Long timeStamp, final EventType eventType,
    		final EventStatus eventStatus, final String authToken, final ServiceType service, final ModuleType module, final String customId,
    		final String searchDetail1, final String searchDetail2, final Map<String, Object> additionalDetails) {
    	this.pk = GUIDGenerator.generateGUID(this);
    	this.nodeId = nodeId;
    	this.sequenceNumber = sequenceNumber;
    	this.timeStamp = timeStamp;
    	this.eventType = eventType.toString();
    	this.eventStatus = eventStatus.toString();
    	this.authToken = authToken;
    	this.service = service.toString();
    	this.module = module.toString();
    	this.customId = customId;
    	this.searchDetail1 = searchDetail1;
    	this.searchDetail2 = searchDetail2;
    	setMapAdditionalDetails(additionalDetails);
    }

    /** @return the primary key */
    public String getPk() {
    	return pk;
    }

    /** @param pk is the primary key */
    public void setPk(final String pk) {
    	this.pk = pk;
    }

	@Override
    public String getNodeId() {
        return nodeId;
    }

    /** @param nodeId The node identifier that this log record comes from. */
    public void setNodeId(final String nodeId) {
        this.nodeId = nodeId;
    }

	@Override
    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    /** @param sequenceNumber This log sequence number MUST be unique. */
    public void setSequenceNumber(final Long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

	@Override
    public Long getTimeStamp() {
    	return timeStamp;
    }

    /** @param timeStamp Sets Timestamp to this value. */
    public void setTimeStamp(final Long timeStamp) {
    	this.timeStamp = timeStamp;
    }

    /** @return event type string. @see EventTypes */
    public String getEventType() {
    	return eventType;
    }

    /**
     * Sets event type. @see EventTypes
     * @param eventType should match the enumeration names.
     */
    public void setEventType(final String eventType) {
        this.eventType = eventType;
    }

    /** @return event status. @see EventStatusEnum */
    public String getEventStatus() {
        return eventStatus;
    }

    @Transient
    @Override
    public EventStatus getEventStatusValue() {
        return EventStatus.valueOf(getEventStatus());
    }

    /** Sets event type. @see EventStatusEnum
     * @param eventType should match the enumeration names.
     */
    public void setEventStatus(final String eventStatus) {
    	this.eventStatus = eventStatus;
    }

	@Override
    public String getAuthToken() {
        return authToken;
    }

    /**
     * Sets the user that triggered the creation of a log
     *
     * @param userId user id. Normally obtained by the following example: authenticationToken.toString()
     */
    public void setAuthToken(final String authToken) {
        this.authToken = authToken;
    }

    /**
     * Gets service type. @see ServiceTypes
     * 
     * @return
     */
    public String getService() {
        return service;
    }

    /**
     * Sets service type. @see ServiceTypes
     * 
     * @param service
     */
    public void setService(final String service) {
        this.service = service;
    }

    /**
     * Gets module type. @see ModuleTypes
     *
     * @return module type.
     */
    public String getModule() {
        return module;
    }

    /**
     * Sets module type. @see ModuleTypes
     *
     * @param module Module type.
     */
    public void setModule(final String module) {
        this.module = module;
    }

	@Override
    public String getCustomId() {
        return customId;
    }

    public void setCustomId(final String customId) {
        this.customId = customId;
    }

	@Override
    public String getSearchDetail1() {
        return searchDetail1;
    }

    public void setSearchDetail1(final String searchDetail1) {
        this.searchDetail1 = searchDetail1;
    }

	@Override
    public String getSearchDetail2() {
        return searchDetail2;
    }

    public void setSearchDetail2(final String searchDetail2) {
        this.searchDetail2 = searchDetail2;
    }

    @Transient
    public String getUnescapedRndValue(){
        String value = getAdditionalDetails();
        if (StringUtils.isNotEmpty(value)) {
            return CertTools.getUnescapedRdnValue(value);
        } else {
            return value;
        }
    }

    /** @return additional details in raw format. */
    public String getAdditionalDetails() {
        return additionalDetails;
    }

    /** Sets additional details in raw format. */
    public void setAdditionalDetails(final String additionalDetails) {
        this.additionalDetails = additionalDetails;
    }

    // @Version @Column
    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    // @Column @Lob
	@Override
    public String getRowProtection() {
        return rowProtection;
    }

	@Override
    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    /** @return additional details. */
    @Transient
	@Override
    public Map<String, Object> getMapAdditionalDetails() {
    	// TODO: Decide on which implementation to use for serialization of the additional details
        return XmlSerializer.decode(getUnescapedRndValue());
    }

    /** @param additionalDetails additional details. */
    @Transient
    public void setMapAdditionalDetails(final Map<String, Object> additionalDetails) {
    	// TODO: Decide on which implementation to use for serialization of the additional details
    	setAdditionalDetails(XmlSerializer.encode(additionalDetails));
    	//setAdditionalDetails(JsonSerializer.toJSON(additionalDetails));
    }

	//
	// Start Database integrity protection methods
	//
	
	@Transient
	@Override
	protected String getProtectString(final int version) {
		final ProtectionStringBuilder build = new ProtectionStringBuilder();
		// What is important to protect here is the data that we define
		// rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
		build.append(getPk()).append(getNodeId()).append(getSequenceNumber()).append(getTimeStamp());
		build.append(getEventType()).append(getEventStatus()).append(getAuthToken()).append(getService()).append(getModule());
		build.append(getCustomId()).append(getSearchDetail1()).append(getSearchDetail2()).append(getAdditionalDetails());
		return build.toString();
	}

	@Transient
	@Override
	protected int getProtectVersion() {
		return 1;
	}

	@PrePersist
	@PreUpdate
	@Override
	protected void protectData() throws DatabaseProtectionException {
		super.protectData();
	}
	
	@PostLoad
	@Override
	protected void verifyData() throws DatabaseProtectionException {
		super.verifyData();
	}

	@Override 
    @Transient
	protected String getRowId() {
		return getPk();
	}
	//
	// End Database integrity protection methods
	//

	@Override
    @Transient
	public EventType getEventTypeValue() {
		return new EventTypeHolder(getEventType());
	}

	@Override
    @Transient
	public ModuleType getModuleTypeValue() {
		return new ModuleTypeHolder(getModule());
	}

	@Override
    @Transient
	public ServiceType getServiceTypeValue() {
		return new ServiceTypeHolder(getService());
	}
}
