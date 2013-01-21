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
package org.cesecore.audit;

import java.util.Map;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;

/**
 * Stored log dta that should be searchable should implement this interface.
 * 
 * @version $Id$
 */
public interface AuditLogEntry {

	/* Database column names that AuditLogDevices might implement. Used to build custom queries. */
	public static final String FIELD_TIMESTAMP            = "timeStamp";
	public static final String FIELD_EVENTTYPE            = "eventType";
	public static final String FIELD_EVENTSTATUS          = "eventStatus";
	public static final String FIELD_AUTHENTICATION_TOKEN = "authToken";
	public static final String FIELD_SERVICE              = "service";
	public static final String FIELD_MODULE               = "module";
	public static final String FIELD_CUSTOM_ID            = "customId";
	public static final String FIELD_SEARCHABLE_DETAIL1   = "searchDetail1";
	public static final String FIELD_SEARCHABLE_DETAIL2   = "searchDetail2";
	public static final String FIELD_ADDITIONAL_DETAILS   = "additionalDetails";
	public static final String FIELD_SEQUENCENUMBER        = "sequenceNumber";
	public static final String FIELD_NODEID               = "nodeId";
	
	/** @return epoch GMT timestamp when log was created. */
	Long getTimeStamp();

	/** @return event type. @see EventTypes */
	EventType getEventTypeValue();

	/** @return event status. @see EventStatus */
	EventStatus getEventStatusValue();

	/** @return the authentication token that triggered the creation of a log. */
	String getAuthToken();

	/** @return service type. @see ServiceTypes */
	ServiceType getServiceTypeValue();

	/** @return module type. @see ModuleTypes */
	ModuleType getModuleTypeValue();

	/** @return a custom identifier (e.g. CA Id) */
	String getCustomId();

	/** @return searchable detail1 (e.g. certificate serialnumber)*/
	String getSearchDetail1();

	/** @return searchable detail2 (e.g. username) */
	String getSearchDetail2();

	/** @return map of additional (non-searchable) details. */
	Map<String, Object> getMapAdditionalDetails();

	/** @return log sequence number. */
	Long getSequenceNumber();

	/** @return node identifier to be used together with sequenceNumber. */
	String getNodeId();
}
