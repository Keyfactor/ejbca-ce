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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.ejbca.core.model.services.CustomServiceWorkerProperty;
import org.ejbca.core.model.services.CustomServiceWorkerUiSupport;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.ui.web.admin.CustomLoader;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Class used to populate the fields in the customworker.xhtml subview page. 
 * 
 * Is compatible with custom action and custom interval. 
 *
 * @version $Id$
 */
public class CustomWorkerType extends WorkerType {
    
    private static final Logger log = Logger.getLogger(CustomWorkerType.class);

	
	private static final long serialVersionUID = 1790314768357040269L;
    public static final String NAME = "CUSTOMWORKER";
	
    private String autoClassPath;
    private String manualClassPath;
    private String propertyText;
    private Collection<String> compatibleActionTypeNames = new ArrayList<>();
    private Collection<String> compatibleIntervalTypeNames = new ArrayList<>();
    private ListDataModel<CustomServiceWorkerProperty> customUiPropertyListDataModel = null;

	public CustomWorkerType() {
		super(ServiceTypeUtil.CUSTOMWORKER_SUB_PAGE, NAME, true);
		
		compatibleActionTypeNames.add(CustomActionType.NAME);
		compatibleActionTypeNames.add(NoActionType.NAME);
		compatibleActionTypeNames.add(MailActionType.NAME);
		
		compatibleIntervalTypeNames.add(CustomIntervalType.NAME);
		compatibleIntervalTypeNames.add(PeriodicalIntervalType.NAME);
	}

	/**
	 * @return the propertyText
	 */
	public String getPropertyText() {
		return propertyText;
	}

	/**
	 * @param propertyText the propertyText to set
	 */
	public void setPropertyText(String propertyText) {
		this.propertyText = propertyText;
	}

	/**
	 * Sets the class path, and detects if it is an auto-detected class
	 * or a manually specified class.
	 */
	public void setClassPath(String classPath) {
	    if (CustomLoader.isDisplayedInList(classPath, IWorker.class)) {
            autoClassPath = classPath;
            manualClassPath = "";
	    } else {
            autoClassPath = "";
            manualClassPath = classPath;
	    }
	}

	@Override
	public String getClassPath() {
		return autoClassPath != null && !autoClassPath.isEmpty() ? autoClassPath : manualClassPath;
	}
	
	public void setAutoClassPath(String classPath) {
        autoClassPath = classPath;
    }

    public String getAutoClassPath() {
        return autoClassPath;
    }
    
    public void setManualClassPath(String classPath) {
        manualClassPath = classPath;
    }

    public String getManualClassPath() {
        return manualClassPath;
    }

    @Override
	@SuppressWarnings("unchecked")
    public Properties getProperties(final ArrayList<String> errorMessages) throws IOException{
		final Properties retval = new Properties();
		if (customUiPropertyListDataModel==null) {
            retval.load(new ByteArrayInputStream(getPropertyText().getBytes()));        
		} else {
		    for (final CustomServiceWorkerProperty customUiProperty : (List<CustomServiceWorkerProperty>)customUiPropertyListDataModel.getWrappedData()) {
	            retval.setProperty(customUiProperty.getName(), customUiProperty.getValue());
		    }
		}
		return retval;
	}
	
    @Override
	public void setProperties(Properties properties) throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();		
		properties.store(baos, null);		
		setPropertyText(new String(baos.toByteArray()));
	}
	
	/**
	 * @return the names of the Compatible Action Types
	 */
    @Override
	public Collection<String> getCompatibleActionTypeNames() {
		return compatibleActionTypeNames;
	}

	/**
	 * @return the names of the Compatible Interval Types
	 */
    @Override
	public Collection<String> getCompatibleIntervalTypeNames() {
		return compatibleIntervalTypeNames;
	}
	
    @Override
	public boolean isCustom() {
		return true;
	}

	public boolean isCustomUiRenderingSupported() {
	    return isCustomUiRenderingSupported(getClassPath());
	}
	
	public static boolean isCustomUiRenderingSupported(final String classPath) {
        try {
            return Arrays.asList(Class.forName(classPath).getInterfaces()).contains(CustomServiceWorkerUiSupport.class);
        } catch (ClassNotFoundException e) {
            return false;
        }
	}
		
	public ListDataModel<CustomServiceWorkerProperty> getCustomUiPropertyList() {
	    if (isCustomUiRenderingSupported()) {
	        if (customUiPropertyListDataModel==null) {
	            final List<CustomServiceWorkerProperty> customUiPropertyList = new ArrayList<>();
	            try {
	                final CustomServiceWorkerUiSupport customPublisherUiSupport = (CustomServiceWorkerUiSupport) Class.forName(getClassPath()).newInstance();
	                final Properties currentProperties = new Properties();
	                currentProperties.load(new ByteArrayInputStream(getPropertyText().getBytes()));
	                customUiPropertyList.addAll(customPublisherUiSupport.getCustomUiPropertyList(EjbcaJSFHelper.getBean().getAdmin(), currentProperties, EjbcaJSFHelper.getBean().getText()));
	            } catch (InstantiationException | IllegalAccessException | ClassNotFoundException | IOException e) {
	                log.error("Error while getting the custom publisher ui support!", e);
	            } 
	            this.customUiPropertyListDataModel = new ListDataModel<>(customUiPropertyList);
            }
	    }
	    return customUiPropertyListDataModel;
	}
	
    public List<SelectItem> getCustomUiPropertySelectItems() {
        final List<SelectItem> ret = new ArrayList<>();
        if (getCustomUiPropertyList() != null && getCustomUiPropertyList().isRowAvailable()) {
            final CustomServiceWorkerProperty customServiceWorkerProperty = getCustomUiPropertyList().getRowData();
            if (customServiceWorkerProperty.getOptions() != null) {
                for (int i = 0; i < customServiceWorkerProperty.getOptions().size(); i++) {
                    ret.add(new SelectItem(customServiceWorkerProperty.getOptions().get(i), customServiceWorkerProperty.getOptionTexts().get(i)));
                }
            }
        }
        return ret;
    }
	
	public String getCustomUiTitleText() {
        final String customClassSimpleName = getClassPath().substring(getClassPath().lastIndexOf('.')+1);
	    return EjbcaJSFHelper.getBean().getText().get(customClassSimpleName.toUpperCase() + "_TITLE");
	}

    public String getCustomUiPropertyText() {
        final String customClassSimpleName = getClassPath().substring(getClassPath().lastIndexOf('.')+1);
        String name = "";
        if (getCustomUiPropertyList()!= null && getCustomUiPropertyList().isRowAvailable()) {
            name = (getCustomUiPropertyList().getRowData()).getName().replaceAll("\\.", "_");
        }
        return EjbcaJSFHelper.getBean().getText().get(customClassSimpleName.toUpperCase() + "_" + name.toUpperCase());
    }
    
    public String getCustomUiPropertyHelpText() {
        final String customClassSimpleName = getClassPath().substring(getClassPath().lastIndexOf('.')+1);
        String name = "";
        if (getCustomUiPropertyList()!= null && getCustomUiPropertyList().isRowAvailable()) {
            name = (getCustomUiPropertyList().getRowData()).getName().replaceAll("\\.", "_");
        } 
        return EjbcaJSFHelper.getBean().getText().get(customClassSimpleName.toUpperCase() + "_" + name.toUpperCase() + "_HELP");
    }
    
    public boolean isCustomUiPropertyHelpTextRendered() {
        return !getCustomUiPropertyHelpText().contains("_HELP");
    }
}
