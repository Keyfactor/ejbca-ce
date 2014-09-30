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

import java.util.List;

import javax.faces.model.SelectItem;

/**
 * 
 * @version $Id$
 */
public class AuditSearchCondition {
	
	private Operation operation = Operation.AND;
	private final String column;
	private Condition condition = Condition.EQUALS;
	private String value;

	private final List<SelectItem> options;

	public AuditSearchCondition(String column, Condition condition, String defaultValue) {
		this.column = column;
		this.options = null;
		this.value = defaultValue;
		this.condition = condition;
	}

	public AuditSearchCondition(String column, List<SelectItem> options) {
		this.column = column;
		this.options = options;
	}

	public void setOperation(Operation operation) {
		this.operation = operation;
	}

	public Operation getOperation() {
		return operation;
	}

	public String getColumn() {
		return column;
	}

	public void setCondition(String condition) {
		this.condition = Condition.valueOf(condition);
	}

	public String getCondition() {
		return condition.name();
	}

	public void setValue(String value) {
		this.value = value;
	}

	public String getValue() {
		return value;
	}

	public List<SelectItem> getOptions() {
		return options;
	}
}
