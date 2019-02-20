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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.faces.model.SelectItem;

import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Class used to populate the fields in the custominterval.xhtml subview page. 
 * 
 *
 * @version $Id$
 */
public class PeriodicalIntervalType extends IntervalType {
	
	private static final long serialVersionUID = -1076212040665563240L;

    public static final String NAME = "PERIODICALINTERVAL";
	
	public static final String DEFAULT_UNIT = PeriodicalInterval.UNIT_MINUTES;
	public static final String DEFAULT_VALUE = "5";
	
    private String unit;
    private String value;
	
	public PeriodicalIntervalType() {
		super(ServiceTypeUtil.PERIODICALINTERVAL_SUB_PAGE, NAME, true);
		this.unit = DEFAULT_UNIT;
		this.value = DEFAULT_VALUE;
	}

	@Override
	public String getClassPath() {
		return org.ejbca.core.model.services.intervals.PeriodicalInterval.class.getName();
	}

	@Override
	public Properties getProperties(ArrayList<String> errorMessages) throws IOException{
		Properties retval = new Properties();
		
		
		try{
			int val = Integer.parseInt(value);
			if(val < 1){
				throw new NumberFormatException();
			}
		}catch(NumberFormatException e){
			errorMessages.add("PERIODICALVALUEERROR");
		}
	    retval.setProperty(PeriodicalInterval.PROP_VALUE, value);
	    retval.setProperty(PeriodicalInterval.PROP_UNIT, unit);
		return retval;
	}
	
	@Override
	public void setProperties(Properties properties) throws IOException{
		value = properties.getProperty(PeriodicalInterval.PROP_VALUE,DEFAULT_VALUE);
		unit = properties.getProperty(PeriodicalInterval.PROP_UNIT,DEFAULT_UNIT);
	}

	@Override
	public boolean isCustom() {
		return false;
	}

	public String getUnit() {
		return unit;
	}

	public void setUnit(String unit) {
		this.unit = unit;
	}
	
	public List<SelectItem> getAvailableUnits(){
		final List<SelectItem> retval = new ArrayList<>(PeriodicalInterval.AVAILABLE_UNITS.length);
		for (final String key : PeriodicalInterval.AVAILABLE_UNITS) {
            retval.add(new SelectItem(key, EjbcaJSFHelper.getBean().getText().get(key).toLowerCase()));
		}
		return retval;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}
	
	
}
