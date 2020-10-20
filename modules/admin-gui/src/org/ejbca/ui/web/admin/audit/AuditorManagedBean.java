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
package org.ejbca.ui.web.admin.audit;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.faces.context.FacesContext;
import javax.faces.event.ActionEvent;
import javax.faces.model.SelectItem;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditDevicesConfig;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.impl.AuditExporterXml;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.XmlSerializer;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceResponse;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

/**
 * JSF Backing bean for viewing security audit logs.
 * 
 * Reloads the data lazily if when requested if something was cause for an update (first time, user has invoked reload etc).
 * 
 * getConditions() will handle special cases when HTTP GET parameters are passed (e.g. show history for a username).
 * 
 */
public class AuditorManagedBean extends BaseManagedBean implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(AuditorManagedBean.class);

	private static final boolean ORDER_ASC = true;
	private static final boolean ORDER_DESC = false;
	
	private final SecurityEventsAuditorSessionLocal securityEventsAuditorSession = new EjbLocalHelper().getSecurityEventsAuditorSession();
	private final CaSessionLocal caSession = new EjbLocalHelper().getCaSession();
	
	private boolean renderNext = false;

	private boolean reloadResultsNextView = true;
	private String device;
	private String sortColumn = AuditLogEntry.FIELD_TIMESTAMP;
	private boolean sortOrder = ORDER_DESC;
	private int maxResults = 40;
	private int startIndex = 1;
	private final List<SelectItem> sortColumns = new ArrayList<>();
	private final List<SelectItem> columns = new ArrayList<>();
	private final List<SelectItem> sortOrders = new ArrayList<>();
	private List<? extends AuditLogEntry> results;
	private Map<Object, String> caIdToNameMap;

	private Map<String, String> columnNameMap = new HashMap<>();
	private final List<SelectItem> eventStatusOptions = new ArrayList<>();
	private final List<SelectItem> eventTypeOptions = new ArrayList<>();
	private final List<SelectItem> moduleTypeOptions = new ArrayList<>();
	private final List<SelectItem> serviceTypeOptions = new ArrayList<>();
	private final List<SelectItem> operationsOptions = new ArrayList<>();
	private final List<SelectItem> conditionsOptions = new ArrayList<>();
    private final List<SelectItem> conditionsOptionsExact = new ArrayList<>();
    private final List<SelectItem> conditionsOptionsContains = new ArrayList<>();
    private final List<SelectItem> conditionsOptionsNumber = new ArrayList<>();
    private final List<SelectItem> cmsSigningCaOptions = new ArrayList<>();
    private Integer cmsSigningCa = null;
	private String conditionColumn = AuditLogEntry.FIELD_SEARCHABLE_DETAIL2;
	private AuditSearchCondition conditionToAdd;
	private List<AuditSearchCondition> conditions = new ArrayList<>();
	private boolean automaticReload = true;
	
	public AuditorManagedBean() {
	    super(AccessRulesConstants.ROLE_ADMINISTRATOR, AuditLogRules.VIEW.resource());
		final EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();
		columnNameMap.put(AuditLogEntry.FIELD_AUTHENTICATION_TOKEN, ejbcaWebBean.getText("ADMINISTRATOR"));
		columnNameMap.put(AuditLogEntry.FIELD_CUSTOM_ID, ejbcaWebBean.getText("CUSTOM_ID"));
		columnNameMap.put(AuditLogEntry.FIELD_EVENTSTATUS, ejbcaWebBean.getText("EVENTSTATUS"));
		columnNameMap.put(AuditLogEntry.FIELD_EVENTTYPE, ejbcaWebBean.getText("EVENTTYPE"));
		columnNameMap.put(AuditLogEntry.FIELD_MODULE, ejbcaWebBean.getText("MODULE"));
		columnNameMap.put(AuditLogEntry.FIELD_NODEID, ejbcaWebBean.getText("NODE"));
		columnNameMap.put(AuditLogEntry.FIELD_SEARCHABLE_DETAIL1, ejbcaWebBean.getText("CERTIFICATE"));
		columnNameMap.put(AuditLogEntry.FIELD_SEARCHABLE_DETAIL2, ejbcaWebBean.getText("USERNAME_ABBR"));
		//columnNameMap.put(AuditLogEntry.FIELD_SEQUENCENUMBER, ejbcaWebBean.getText("SEQUENCENUMBER"));
		//columnNameMap.put(AuditLogEntry.FIELD_SERVICE, ejbcaWebBean.getText("SERVICE"));
		columnNameMap.put(AuditLogEntry.FIELD_TIMESTAMP, ejbcaWebBean.getText("TIMESTAMP"));
		for (final Entry<String,String> entry : columnNameMap.entrySet()) {
			sortColumns.add(new SelectItem(entry.getKey(), entry.getValue()));
		}
		columnNameMap.put(AuditLogEntry.FIELD_ADDITIONAL_DETAILS, ejbcaWebBean.getText("ADDITIONAL_DETAILS"));
		columns.addAll(sortColumns);
	    //Commented out due to the fact that searching through the details field is unreliable. If there are any non ascii-characters in the field,
        // (such as é), it will in its entirety be b64-encoded, which renders it unsearchable, even for ascii characters that may happen to be there
        // as well.
		//columns.add(new SelectItem(AuditLogEntry.FIELD_ADDITIONAL_DETAILS, columnNameMap.get(AuditLogEntry.FIELD_ADDITIONAL_DETAILS)));
		sortOrders.add(new SelectItem(ORDER_ASC, "ASC"));
		sortOrders.add(new SelectItem(ORDER_DESC, "DESC"));
		// If no device is chosen we select the first available as default
		if (getDevices().size()>0) {
			device = (String) getDevices().get(0).getValue();
		}
		// We can't use enums directly in JSF 1.2
		for (Operation current : Operation.values()) {
			operationsOptions.add(new SelectItem(current.toString(), ejbcaWebBean.getText(current.toString())));
		}
		for (Condition current : Condition.values()) {
			conditionsOptions.add(new SelectItem(current.toString(), ejbcaWebBean.getText(current.toString())));
		}
        conditionsOptionsExact.add(new SelectItem(Condition.EQUALS.toString(), ejbcaWebBean.getText(Condition.EQUALS.toString())));
        conditionsOptionsExact.add(new SelectItem(Condition.NOT_EQUALS.toString(), ejbcaWebBean.getText(Condition.NOT_EQUALS.toString())));
        conditionsOptionsNumber.addAll(conditionsOptionsExact);
        conditionsOptionsNumber.add(new SelectItem(Condition.GREATER_THAN.toString(), ejbcaWebBean.getText(Condition.GREATER_THAN.toString())));
        conditionsOptionsNumber.add(new SelectItem(Condition.LESS_THAN.toString(), ejbcaWebBean.getText(Condition.LESS_THAN.toString())));
        conditionsOptionsContains.add(new SelectItem(Condition.CONTAINS.toString(), ejbcaWebBean.getText(Condition.CONTAINS.toString())));
		for (EventStatus current : EventStatus.values()) {
			eventStatusOptions.add(new SelectItem(current.toString(), ejbcaWebBean.getText(current.toString())));
		}
		for (EventTypes current : EventTypes.values()) {
			// TODO: Verify if these are used by EJBCA
			switch (current) {
			case BACKUP:
			case RESTORE:
			case TIME_SYNC_ACQUIRE:
			case TIME_SYNC_LOST:
			//case LOG_MANAGEMENT_CHANGE:
			//case LOG_SIGN:
			case CERTIFICATE_KEY_BIND:
			case CERTIFICATE_KEY_UNBIND:
				// Ignore!
				break;
			default:
				eventTypeOptions.add(new SelectItem(current.toString(), ejbcaWebBean.getText(current.toString())));
			}
		}
		for (EventType current : EjbcaEventTypes.values()) {
			eventTypeOptions.add(new SelectItem(current.toString(), ejbcaWebBean.getText(current.toString())));
		}
		for (ModuleType current : ModuleTypes.values()) {
			moduleTypeOptions.add(new SelectItem(current.toString(), ejbcaWebBean.getText(current.toString())));
		}
		for (ModuleType current : EjbcaModuleTypes.values()) {
			moduleTypeOptions.add(new SelectItem(current.toString(), ejbcaWebBean.getText(current.toString())));
		}
		for (ServiceType current : ServiceTypes.values()) {
			serviceTypeOptions.add(new SelectItem(current.toString(), ejbcaWebBean.getText(current.toString())));
		}
		for (ServiceType current : EjbcaServiceTypes.values()) {
			serviceTypeOptions.add(new SelectItem(current.toString(), ejbcaWebBean.getText(current.toString())));
		}
		// By default, don't show the authorized to resource events
		conditions.add(new AuditSearchCondition(AuditLogEntry.FIELD_EVENTTYPE, conditionsOptionsExact, eventTypeOptions, Condition.NOT_EQUALS, EventTypes.ACCESS_CONTROL.name()));
		updateCmsSigningCas();
	}

	public List<SelectItem> getDevices() {
		final List<SelectItem> list = new ArrayList<>();
		for (final String deviceId : securityEventsAuditorSession.getQuerySupportingLogDevices()) {
			list.add(new SelectItem(deviceId, deviceId));
		}
		return list;
	}
	
	public boolean isOneLogDevice() {
		return getDevices().size()==1;
	}
	
	public boolean isRenderNext() {
		getResults();
		return renderNext;
	}

	public int getResultSize() {
		getResults();
		return results==null?0:results.size();
	}

	public List<SelectItem> getSortColumns() {
		return sortColumns;
	}

	public List<SelectItem> getSortOrders() {
		return sortOrders;
	}

	public List<SelectItem> getColumns() {
		return columns;
	}

	public void setDevice(final String selectedDevice) {
		this.device = selectedDevice;
	}

	public String getDevice() {
		return device;
	}
	
	public List<? extends AuditLogEntry> getResults() {
		if (getDevice() != null && reloadResultsNextView) {
			reloadResults();
			reloadResultsNextView = false;
		}
		return results;
	}
	
	/** Converts a map with possibly Base64 encoded items to a string */
	public String mapToString(final Map<String,Object> value) {
	    return MapToStringConverter.getAsString(value);
	}

	public void setSortColumn(String sortColumn) {
		this.sortColumn = sortColumn;
	}

	public String getSortColumn() {
		return sortColumn;
	}

	public void setMaxResults(final int maxResults) {
		this.maxResults = Math.min(1000, Math.max(1, maxResults));	// 1-1000 results allowed
	}

	public int getMaxResults() {
		return maxResults;
	}

	public void setStartIndex(final int startIndex) {
		this.startIndex = Math.max(1, startIndex);
	}

	public int getStartIndex() {
		return startIndex;
	}

	public void setSortOrder(boolean sortOrder) {
		this.sortOrder = sortOrder;
	}

	public boolean isSortOrder() {
		return sortOrder;
	}

	public void setConditionColumn(String conditionColumn) {
		this.conditionColumn = conditionColumn;
	}

	public String getConditionColumn() {
		return conditionColumn;
	}

	public void setConditionToAdd(AuditSearchCondition conditionToAdd) {
		this.conditionToAdd = conditionToAdd;
	}

	public AuditSearchCondition getConditionToAdd() {
		return conditionToAdd;
	}

	public void clearConditions() {
		setConditions(new ArrayList<AuditSearchCondition>());
		setConditionToAdd(null);
		onConditionChanged();
	}

	public void newCondition() {
		if (AuditLogEntry.FIELD_AUTHENTICATION_TOKEN.equals(conditionColumn)
				|| AuditLogEntry.FIELD_NODEID.equals(conditionColumn)
				|| AuditLogEntry.FIELD_SEARCHABLE_DETAIL1.equals(conditionColumn)
				|| AuditLogEntry.FIELD_SEARCHABLE_DETAIL2.equals(conditionColumn)
				|| AuditLogEntry.FIELD_SEQUENCENUMBER.equals(conditionColumn)) {
			setConditionToAdd(new AuditSearchCondition(conditionColumn, conditionsOptions, null, Condition.EQUALS, ""));
		} else if (AuditLogEntry.FIELD_CUSTOM_ID.equals(conditionColumn)) {
			List<SelectItem> caIds = new ArrayList<>();
			for (Entry<Object,String> entry : caIdToNameMap.entrySet()) {
				caIds.add(new SelectItem(entry.getKey(), entry.getValue()));
			}
			setConditionToAdd(new AuditSearchCondition(conditionColumn, conditionsOptionsExact, caIds));
		} else if (AuditLogEntry.FIELD_EVENTSTATUS.equals(conditionColumn)) {
			setConditionToAdd(new AuditSearchCondition(conditionColumn, conditionsOptionsExact, eventStatusOptions));
		} else if (AuditLogEntry.FIELD_EVENTTYPE.equals(conditionColumn)) {
			setConditionToAdd(new AuditSearchCondition(conditionColumn, conditionsOptionsExact, eventTypeOptions));
		} else if (AuditLogEntry.FIELD_MODULE.equals(conditionColumn)) {
			setConditionToAdd(new AuditSearchCondition(conditionColumn, conditionsOptionsExact, moduleTypeOptions));
		} else if (AuditLogEntry.FIELD_SERVICE.equals(conditionColumn)) {
			setConditionToAdd(new AuditSearchCondition(conditionColumn, conditionsOptionsExact, serviceTypeOptions));
		} else if (AuditLogEntry.FIELD_TIMESTAMP.equals(conditionColumn)) {
			setConditionToAdd(new AuditSearchCondition(conditionColumn, conditionsOptionsNumber, null, Condition.EQUALS, ValidityDate.formatAsISO8601(new Date(), ValidityDate.TIMEZONE_SERVER)));
        } else if (AuditLogEntry.FIELD_ADDITIONAL_DETAILS.equals(conditionColumn)) {
            setConditionToAdd(new AuditSearchCondition(conditionColumn, conditionsOptionsContains, null, Condition.CONTAINS, ""));
		}
	}

	public void cancelCondition() {
		setConditionToAdd(null);
	}

	public void addCondition() {
		getConditions().add(getConditionToAdd());
		setConditionToAdd(null);
		onConditionChanged();
	}

    public void removeCondition(ActionEvent event){
        getConditions().remove(event.getComponent().getAttributes().get("removeCondition"));
        onConditionChanged();
    }

    public boolean isAutomaticReload() {
        return automaticReload;
    }
    public void setAutomaticReload(boolean automaticReload) {
        this.automaticReload = automaticReload;
    }
    
    private void onConditionChanged() {
        reloadResultsNextView = isAutomaticReload();
        first();
    }

    public void reload()  {
		reloadResultsNextView = true;
	}

	private void reloadResults() {
		if (log.isDebugEnabled()) {
			log.debug("Reloading audit load. selectedDevice=" + device);
		}
	    updateCaIdToNameMap();
		try {
	        final AuthenticationToken authenticationToken = EjbcaJSFHelper.getBean().getEjbcaWebBean().getAdminObject();
	        results = getResults(authenticationToken, columnNameMap.keySet(), device, getConditions(), sortColumn, sortOrder, startIndex-1, maxResults);
		} catch (Exception e) {
		    if (results!=null) {
	            results.clear();
		    }
		    if (log.isDebugEnabled()) {
		        log.debug(e.getMessage(), e);
		    }
            addNonTranslatedErrorMessage("Invalid search conditions: " + e.getMessage());
		}
		renderNext = results!=null && !results.isEmpty() && results.size()==maxResults;
	}
	
    /**
     * Build and executing audit log queries that are safe from SQL injection.
     * 
     * @param token the requesting entity. Will also limit the results to authorized CAs. 
     * @param validColumns a Set of legal column names
     * @param device the name of the audit log device
     * @param conditions the list of conditions to transform into a query
     * @param sortColumn ORDER BY column
     * @param sortOrder true=ASC, false=DESC order
     * @param firstResult first entry from the result set. Index starts with 0.
     * @param maxResults number of results to return
     * @return the query result
     * @throws AuthorizationDeniedException if the administrator is not authorized to perform the requested query
     */
    private List<? extends AuditLogEntry> getResults(final AuthenticationToken token, final Set<String> validColumns, final String device,
            final List<AuditSearchCondition> conditions, final String sortColumn, final boolean sortOrder, final int firstResult, final int maxResults)
            throws AuthorizationDeniedException {
        final List<Object> parameters = new ArrayList<>();
        final StringBuilder whereClause = new StringBuilder();
        final String errorMessage = "This should never happen unless you are intentionally trying to perform an SQL injection attack.";
        for (int i=0; i<conditions.size(); i++) {
            final AuditSearchCondition condition = conditions.get(i);
            if (i>0) {
                switch (condition.getOperation()) {
                case AND:
                    whereClause.append(" AND "); break;
                case OR:
                    whereClause.append(" OR "); break;
                }
            }
            // Validate that the column we are adding to the SQL WHERE clause is exactly one of the legal column names
            if (!validColumns.contains(condition.getColumn())) {
                throw new IllegalArgumentException(errorMessage);
            }
            Object conditionValue = condition.getValue();
            if (AuditLogEntry.FIELD_TIMESTAMP.equals(condition.getColumn())) {
                try {
                    conditionValue = Long.valueOf(ValidityDate.parseAsIso8601(conditionValue.toString()).getTime());
                } catch (ParseException e) {
                    log.debug("Admin entered invalid date for audit log search: " + condition.getValue());
                    continue;
                }
            }
            switch (Condition.valueOf(condition.getCondition())) {
            case EQUALS:
                whereClause.append("a.").append(condition.getColumn()).append(" = ?").append(i); break;
            case NOT_EQUALS:
                whereClause.append("a.").append(condition.getColumn()).append(" != ?").append(i); break;
            case CONTAINS:
                whereClause.append("a.").append(condition.getColumn()).append(" LIKE ?").append(i);
                conditionValue = "%" + conditionValue + "%";
                break;
            case ENDS_WITH:
                whereClause.append("a.").append(condition.getColumn()).append(" LIKE ?").append(i);
                conditionValue = "%" + conditionValue;
                break;
            case STARTS_WITH:
                whereClause.append("a.").append(condition.getColumn()).append(" LIKE ?").append(i);
                conditionValue = conditionValue + "%";
                break;
            case GREATER_THAN:
                whereClause.append("a.").append(condition.getColumn()).append(" > ?").append(i); break;
            case LESS_THAN:
                whereClause.append("a.").append(condition.getColumn()).append(" < ?").append(i); break;
            default:
                throw new IllegalArgumentException(errorMessage);    
            }
            // The condition value will be added to the query using JPA's setParameter (safe from SQL injection)
            parameters.add(conditionValue);
        }
        // Validate that the column we are adding to the SQL ORDER clause is exactly one of the legal column names
        if (!validColumns.contains(sortColumn)) {
            throw new IllegalArgumentException(errorMessage);
        }
        final String orderClause = new StringBuilder("a.").append(sortColumn).append(sortOrder?" ASC":" DESC").toString();
        return new EjbLocalHelper().getEjbcaAuditorSession().selectAuditLog(token, device, firstResult, maxResults, whereClause.toString(), orderClause, parameters);
    }
	
	public Map<Object, String> getCaIdToName() {
		return caIdToNameMap;
	}

	private void updateCaIdToNameMap() {
		final Map<Integer, String> map = caSession.getCAIdToNameMap();
		final Map<Object, String> ret = new HashMap<>();
		final AuthenticationToken authenticationToken = EjbcaJSFHelper.getBean().getEjbcaWebBean().getAdminObject();
		for (final Entry<Integer,String> entry : map.entrySet()) {
            if (caSession.authorizedToCANoLogging(authenticationToken, entry.getKey())) {
                ret.put(entry.getKey().toString(), entry.getValue());
            }
		}
		caIdToNameMap = ret;
	}

	public Map<String, String> getNameFromColumn() {
		return columnNameMap;
	}

	public void first() {
		setStartIndex(1);
		reloadResultsNextView = true;
	}

	public void next(){
		setStartIndex(startIndex + maxResults);
		reloadResultsNextView = true;
	}

	public void previous() {
		setStartIndex(startIndex - maxResults);
		reloadResultsNextView = true;
	}

	public void setConditions(List<AuditSearchCondition> conditions) {
		this.conditions = conditions;
	}

	public List<AuditSearchCondition> getConditions() {
		// Special case when we supply "username" as parameter to allow view of a user's history
		final String searchDetail2String = getHttpParameter("username");
		if (searchDetail2String!=null) {
			reloadResultsNextView = true;
			startIndex = 1;
			conditions.clear();
			conditions.add(new AuditSearchCondition(AuditLogEntry.FIELD_SEARCHABLE_DETAIL2, conditionsOptions, null, Condition.EQUALS, searchDetail2String));
			sortColumn = AuditLogEntry.FIELD_TIMESTAMP;
			sortOrder = ORDER_DESC;
		}
		return conditions;
	}

	public List<SelectItem> getDefinedOperations() {
		return operationsOptions;
	}

	public List<SelectItem> getDefinedConditions() {
	    return conditionToAdd.getConditions();
	}

	private String getHttpParameter(String key) {
		return FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get(key);
	}
	
	public void reorderAscByTime() { reorderBy(AuditLogEntry.FIELD_TIMESTAMP, ORDER_ASC); }
	public void reorderDescByTime() { reorderBy(AuditLogEntry.FIELD_TIMESTAMP, ORDER_DESC); }

	public void reorderAscByEvent() { reorderBy(AuditLogEntry.FIELD_EVENTTYPE, ORDER_ASC); }
	public void reorderDescByEvent() { reorderBy(AuditLogEntry.FIELD_EVENTTYPE, ORDER_DESC); }

	public void reorderAscByStatus() { reorderBy(AuditLogEntry.FIELD_EVENTSTATUS, ORDER_ASC); }
	public void reorderDescByStatus() { reorderBy(AuditLogEntry.FIELD_EVENTSTATUS, ORDER_DESC); }

	public void reorderAscByAuthToken() { reorderBy(AuditLogEntry.FIELD_AUTHENTICATION_TOKEN, ORDER_ASC); }
	public void reorderDescByAuthToken() { reorderBy(AuditLogEntry.FIELD_AUTHENTICATION_TOKEN, ORDER_DESC); }

	public void reorderAscByModule() { reorderBy(AuditLogEntry.FIELD_MODULE, ORDER_ASC); }
	public void reorderDescByModule() { reorderBy(AuditLogEntry.FIELD_MODULE, ORDER_DESC); }

	public void reorderAscByCustomId() { reorderBy(AuditLogEntry.FIELD_CUSTOM_ID, ORDER_ASC); }
	public void reorderDescByCustomId() { reorderBy(AuditLogEntry.FIELD_CUSTOM_ID, ORDER_DESC); }

	public void reorderAscBySearchDetail1() { reorderBy(AuditLogEntry.FIELD_SEARCHABLE_DETAIL1, ORDER_ASC); }
	public void reorderDescBySearchDetail1() { reorderBy(AuditLogEntry.FIELD_SEARCHABLE_DETAIL1, ORDER_DESC); }

	public void reorderAscBySearchDetail2() { reorderBy(AuditLogEntry.FIELD_SEARCHABLE_DETAIL2, ORDER_ASC); }
	public void reorderDescBySearchDetail2() { reorderBy(AuditLogEntry.FIELD_SEARCHABLE_DETAIL2, ORDER_DESC); }

	public void reorderAscByNodeId() { reorderBy(AuditLogEntry.FIELD_NODEID, ORDER_ASC); }
	public void reorderDescByNodeId() { reorderBy(AuditLogEntry.FIELD_NODEID, ORDER_DESC); }

	private void reorderBy(String column, boolean orderAsc) {
		if (!sortColumn.equals(column)) {
			reloadResultsNextView = true;
		}
		sortColumn = column;
		if (sortOrder != orderAsc) {
			reloadResultsNextView = true;
		}
		sortOrder = orderAsc ? ORDER_ASC : ORDER_DESC;
	}
	
	/**
	 * Ugly hack to be able to read the length of the resulting String from JSF EL.
	 * 
	 * Example: "#{auditor.stringTooLong[(auditLogEntry.mapAdditionalDetails)] > 50}"
	 * 
	 * TODO: Use javax.faces.model.DataModel instead
	 * 
	 * @return a fake "Map" where the get(Map) returns the length of the output-formatted Map
	 */
	public Map<String,Integer> getStringTooLong() {
		return new Map<String,Integer>() {
			@Override public Integer get(Object key) {
				return new MapToStringConverter().getAsString(null, null, key).length();
			}
			@Override public void clear() { }
			@Override public boolean containsKey(Object key) { return false; }
			@Override public boolean containsValue(Object value) { return false; }
			@Override public Set<Entry<String, Integer>> entrySet() { return null; }
			@Override public boolean isEmpty() { return false; }
			@Override public Set<String> keySet() { return null; }
			@Override public Integer put(String key, Integer value) { return null; }
			@Override public void putAll(Map<? extends String, ? extends Integer> m) { }
			@Override public Integer remove(Object key) { return null; }
			@Override public int size() { return 0; }
			@Override public Collection<Integer> values() { return null; }
		};
	}

    private void updateCmsSigningCas() {
        final Map<Integer, String> map = caSession.getCAIdToNameMap();
        cmsSigningCaOptions.clear();
        for (int caid :  caSession.getAuthorizedCaIds(EjbcaJSFHelper.getBean().getEjbcaWebBean().getAdminObject())) {
            // TODO: Would be nice to check if the CMS signer service is activated here before we add it
            cmsSigningCaOptions.add(new SelectItem(caid, map.get(caid)));
        }
        if (cmsSigningCa == null && !cmsSigningCaOptions.isEmpty()) {
            cmsSigningCa = (Integer) cmsSigningCaOptions.get(0).getValue();
        }
    }
	public List<SelectItem> getCmsSigningCas() {
	    return cmsSigningCaOptions;
	}
	public Integer getCmsSigningCa() {
	    return cmsSigningCa;
	}
	public void setCmsSigningCa(Integer cmsSigningCa) {
	    this.cmsSigningCa = cmsSigningCa;
	}
	public void downloadResultsCms() {
        try {
            if (cmsSigningCa == null) {
                addErrorMessage("AUDIT_INVALIDCMS");
            } else {
                final CmsCAServiceRequest request = new CmsCAServiceRequest(exportToByteArray(), CmsCAServiceRequest.MODE_SIGN);
                final CAAdminSession caAdminSession = new EjbLocalHelper().getCaAdminSession();
                final AuthenticationToken authenticationToken = EjbcaJSFHelper.getBean().getAdmin();
                final CmsCAServiceResponse resp = (CmsCAServiceResponse) caAdminSession.extendedService(authenticationToken, cmsSigningCa, request);
                try {
                    downloadResults(resp.getCmsDocument(), "application/octet-stream", "export-"+results.get(0).getTimeStamp()+".p7m");
                } catch (IOException e) {
                    log.info("Administration tried to export audit log, but failed. " + e.getMessage());
                    addNonTranslatedErrorMessage(e);
                }
            }
        } catch (Exception e) {
            log.info("Administration tried to export audit log, but failed. " + e.getMessage());
            addNonTranslatedErrorMessage(e);
        }
	}

    public void downloadResults() {
        try {
            // text/xml doesn't work since it gets filtered and all non-ASCII bytes get encoded as entities as if they were Latin-1 (ECA-5831)
            downloadResults(exportToByteArray(), "application/octet-stream", "export-"+results.get(0).getTimeStamp()+".xml"); // "application/force-download" is an alternative here..
        } catch (IOException e) {
            log.info("Administration tried to export audit log, but failed. " + e.getMessage());
            addNonTranslatedErrorMessage(e);
        }
    }
    
    private byte[] exportToByteArray() throws IOException {
        // We could extend this without too much problems to allow the admin to choose between different formats.
        // By reading it from the config we could drop a custom exporter in the class-path and use it if configured
        final Class<? extends AuditExporter> exporterClass = AuditDevicesConfig.getExporter(getDevice());
        AuditExporter auditExporter = null;
        if (exporterClass != null) {
            if (log.isDebugEnabled()) {
                log.debug("Using AuditExporter class: " + exporterClass.getName());
            }
            
            try {
                auditExporter = exporterClass.newInstance();
            } catch (Exception e) {
                log.warn("AuditExporter for " + getDevice() + " is not configured correctly.", e);
            }
        }
        
        if (auditExporter==null) {
            if (log.isDebugEnabled()) {
                log.debug("AuditExporter not configured. Using default: " + AuditExporterXml.class.getSimpleName());
            }
            auditExporter = new AuditExporterXml(); // Use Java-friendly XML as default
        }
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            auditExporter.setOutputStream(baos);
            for (final AuditLogEntry auditLogEntry : results) {
                writeToExport(auditExporter, (AuditRecordData) auditLogEntry);
            }
            auditExporter.close();
            return baos.toByteArray();
        }
    }

    /** Uses the provided exporter to generate export data in memory. Responds with the data instead of rendering a new page. */
    private void downloadResults(byte[] b, String contentType, String filename) throws IOException {
            final HttpServletResponse response = (HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse();
            response.setContentType(contentType);
            response.addHeader("Content-Disposition", "attachment; filename=\""+StringTools.stripFilename(filename)+"\"");
            final ServletOutputStream out = response.getOutputStream();
            response.setContentLength(b.length);
            out.write(b);
            out.close();
            FacesContext.getCurrentInstance().responseComplete();   // No further JSF navigation
    }

    // Duplicate of code from org.cesecore.audit.impl.integrityprotected.IntegrityProtectedAuditorSessionBean.writeToExport
    // (unusable from here.. :/)
    /** We want to export exactly like it was stored in the database, to comply with requirements on logging systems where no altering of the original log data is allowed. */
    private void writeToExport(final AuditExporter auditExporter, final AuditRecordData auditRecordData) throws IOException {
        auditExporter.writeStartObject();
        auditExporter.writeField("pk", auditRecordData.getPk());
        auditExporter.writeField(AuditLogEntry.FIELD_NODEID, auditRecordData.getNodeId());
        auditExporter.writeField(AuditLogEntry.FIELD_SEQUENCENUMBER, auditRecordData.getSequenceNumber());
        auditExporter.writeField(AuditLogEntry.FIELD_TIMESTAMP, auditRecordData.getTimeStamp());
        auditExporter.writeField(AuditLogEntry.FIELD_EVENTTYPE, auditRecordData.getEventTypeValue().toString());
        auditExporter.writeField(AuditLogEntry.FIELD_EVENTSTATUS, auditRecordData.getEventStatusValue().toString());
        auditExporter.writeField(AuditLogEntry.FIELD_AUTHENTICATION_TOKEN, auditRecordData.getAuthToken());
        auditExporter.writeField(AuditLogEntry.FIELD_SERVICE, auditRecordData.getServiceTypeValue().toString());
        auditExporter.writeField(AuditLogEntry.FIELD_MODULE, auditRecordData.getModuleTypeValue().toString());
        auditExporter.writeField(AuditLogEntry.FIELD_CUSTOM_ID, auditRecordData.getCustomId());
        auditExporter.writeField(AuditLogEntry.FIELD_SEARCHABLE_DETAIL1, auditRecordData.getSearchDetail1());
        auditExporter.writeField(AuditLogEntry.FIELD_SEARCHABLE_DETAIL2, auditRecordData.getSearchDetail2());
        final Map<String,Object> additionalDetails = XmlSerializer.decode(auditRecordData.getAdditionalDetails());
        final String additionalDetailsEncoded = XmlSerializer.encodeWithoutBase64(additionalDetails);
        auditExporter.writeField(AuditLogEntry.FIELD_ADDITIONAL_DETAILS, additionalDetailsEncoded);
        auditExporter.writeField("rowProtection", auditRecordData.getRowProtection());
        auditExporter.writeEndObject();
    }
}
