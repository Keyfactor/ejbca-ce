/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Class used to populate the fields in the custominterval.jsp subview page. 
 * 
 * @author Philip Vendil 2006 sep 30
 *
 * @version $Id: PeriodicalIntervalType.java 5585 2008-05-01 20:55:00Z anatom $
 */
public class PeriodicalIntervalType extends IntervalType {
	
	public static final String NAME = "PERIODICALINTERVAL";
	
	public static final String DEFAULT_UNIT = PeriodicalInterval.UNIT_MINUTES;
	public static final String DEFAULT_VALUE = "5";
	
	public PeriodicalIntervalType() {
		super("periodicalinterval.jsp", NAME, true);
		unit = DEFAULT_UNIT;
		value = DEFAULT_VALUE;
	}

    String unit;
    String value;


	public String getClassPath() {
		return org.ejbca.core.model.services.intervals.PeriodicalInterval.class.getName();
	}

	public Properties getProperties(ArrayList errorMessages) throws IOException{
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
	
	public void setProperties(Properties properties) throws IOException{
		value = properties.getProperty(PeriodicalInterval.PROP_VALUE,DEFAULT_VALUE);
		unit = properties.getProperty(PeriodicalInterval.PROP_UNIT,DEFAULT_UNIT);
	}

	public boolean isCustom() {
		return false;
	}

	public String getUnit() {
		return unit;
	}

	public void setUnit(String unit) {
		this.unit = unit;
	}
	
	public List getAvailableUnits(){
		ArrayList retval = new ArrayList();
		for(int i = 0 ; i<PeriodicalInterval.AVAILABLE_UNITS.length; i++){
			retval.add(new SelectItem(PeriodicalInterval.AVAILABLE_UNITS[i],(String) EjbcaJSFHelper.getBean().getText().get(PeriodicalInterval.AVAILABLE_UNITS[i])));
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
