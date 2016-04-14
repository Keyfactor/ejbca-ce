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
package org.ejbca.ui.web.admin.services;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;

import javax.faces.application.Application;
import javax.faces.context.FacesContext;
import javax.faces.event.ValueChangeEvent;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.services.IAction;
import org.ejbca.core.model.services.IInterval;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.workers.CRLDownloadWorker;
import org.ejbca.core.model.services.workers.CRLUpdateWorker;
import org.ejbca.core.model.services.workers.CertificateExpirationNotifierWorker;
import org.ejbca.core.model.services.workers.PublishQueueProcessWorker;
import org.ejbca.core.model.services.workers.RenewCAWorker;
import org.ejbca.core.model.services.workers.RolloverWorker;
import org.ejbca.core.model.services.workers.UserPasswordExpireWorker;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.CustomLoader;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.services.servicetypes.ActionType;
import org.ejbca.ui.web.admin.services.servicetypes.BaseEmailNotifyingWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.BaseWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CRLDownloadWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CRLUpdateWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CertificateExpirationNotifierWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.IntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.MailActionType;
import org.ejbca.ui.web.admin.services.servicetypes.PeriodicalIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.PublishQueueWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.RenewCAWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.RolloverWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.UserPasswordExpireWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.WorkerType;

/**
 * Class used to manage the GUI editing of a Service Configuration
 *
 * @version $Id$
 */
public class EditServiceManagedBean extends BaseManagedBean {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EditServiceManagedBean.class);

	private final EjbLocalHelper ejb = new EjbLocalHelper();
	private final CertificateProfileSessionLocal certificateProfileSession = ejb.getCertificateProfileSession();
	private ServiceConfigurationView serviceConfigurationView;
	private String serviceName = "";

    public EditServiceManagedBean() {
        setServiceConfiguration(new ServiceConfiguration());
    }
	
    public static EditServiceManagedBean getBean() {    
    	FacesContext context = FacesContext.getCurrentInstance();
    	Application app = context.getApplication();
    	EditServiceManagedBean value = (EditServiceManagedBean) app.evaluateExpressionGet(context, "#{editService}", EditServiceManagedBean.class);
    	return value;
    }
    
	/** @return the serviceName */
	public String getServiceName() {
		return serviceName;
	}

	/** @param serviceName the serviceName to set */
	public void setServiceName(String serviceName) {
		this.serviceName = serviceName;		
	}

	/** @return the serviceConfigurationView */
	public ServiceConfigurationView getServiceConfigurationView() {
		return serviceConfigurationView;
	}
	
	public void setServiceConfiguration(ServiceConfiguration serviceConfiguration) {
		this.serviceConfigurationView = new ServiceConfigurationView(serviceConfiguration);
	}

	public String save(){
		String retval = "listservices";
		ArrayList<String> errorMessages = new ArrayList<String>();
		try {
			serviceConfigurationView.getServiceConfiguration(errorMessages);
			if(errorMessages.size() == 0){
				ejb.getServiceSession().changeService(getAdmin(), serviceName, serviceConfigurationView.getServiceConfiguration(errorMessages), false);
				ejb.getServiceSession().activateServiceTimer(getAdmin(), serviceName);
			}else{
				Iterator<String> iter = errorMessages.iterator();
				while(iter.hasNext()){
					addErrorMessage(iter.next());
				}
				retval = null;				
			}
		} catch (IOException e) {
			addErrorMessage((String) EjbcaJSFHelper.getBean().getText().get("ERROREDITINGSERVICE") + " " + e.getMessage());
		}
		return retval;
	}
	
	public String cancel(){		
		return "listservices";
	}
	
	public String update(){
		return "editservice";
	}

	/** Help method used to edit data in the custom worker type. */
	public CustomWorkerType getCustomWorkerType(){
		return (CustomWorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(CustomWorkerType.NAME);
	}
	
	/** Help method used to edit data in the custom action type. */
	public CustomActionType getCustomActionType(){
		return (CustomActionType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(CustomActionType.NAME);
	}	
	
	/** Help method used to edit data in the custom interval type. */
	public CustomIntervalType getCustomIntervalType(){
		return (CustomIntervalType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(CustomIntervalType.NAME);
	}
	
	/** 
     * @return true if admin has access to /services/edit
     */
    public boolean getHasEditRights() {
        return ejb.getAccessControlSession().isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.SERVICES_EDIT);
    }
	
	/** Help method used to edit data in the mail action type. */
	public MailActionType getMailActionType(){
		return (MailActionType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(MailActionType.NAME);
	}	
	
	public BaseWorkerType getBaseWorkerType() {
		String name = null;
		try {
			ServiceConfiguration conf = serviceConfigurationView.getServiceConfiguration(new ArrayList<String>());		
			String cp = conf.getWorkerClassPath();
			name = getTypeNameFromClassPath(cp);			
		} catch (IOException e) {
			log.error(e);
		}
		if (log.isDebugEnabled()) {
			log.debug("Get baseWorkerType by name: "+name);
		}
		BaseWorkerType ret = (BaseWorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(name);
		return ret; 		
	}
	
	/** Help method used to edit data in the notifying worker type. */
	public BaseEmailNotifyingWorkerType getNotifyingType(){
		log.trace(">getNotifyingType");
		BaseEmailNotifyingWorkerType ret = null;
		BaseWorkerType type = getBaseWorkerType();	
		if (type instanceof BaseEmailNotifyingWorkerType) {
			ret = (BaseEmailNotifyingWorkerType)type;
		} else {
			// Use default type in order to avoid model update errors when switching to a worker with a different type
			// i.e. switching for example from CertificateExpirationWorker to CRLUpdateWorker
			// We can't return null either so...
			ret =(BaseEmailNotifyingWorkerType)serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(CertificateExpirationNotifierWorkerType.NAME);
		}
		log.trace("<getNotifyingType");
		return ret;
	}

	private String getTypeNameFromClassPath(String cp) {
		log.debug("ClassPath: "+cp);
		String ret = null;
		if ( (cp != null) && cp.equals(CertificateExpirationNotifierWorker.class.getName()) ) {
			ret = CertificateExpirationNotifierWorkerType.NAME;
		}			
		if ( (cp != null) && cp.equals(UserPasswordExpireWorker.class.getName()) ) {
			ret = UserPasswordExpireWorkerType.NAME;
		}			
		if ( (cp != null) && cp.equals(RenewCAWorker.class.getName()) ) {
			ret = RenewCAWorkerType.NAME;
		}			
		if ( (cp != null) && cp.equals(RolloverWorker.class.getName()) ) {
            ret = RolloverWorkerType.NAME;
        }
		if ( (cp != null) && cp.equals(PublishQueueProcessWorker.class.getName()) ) {
			ret = PublishQueueWorkerType.NAME;
		}			
		if ( (cp != null) && cp.equals(CRLUpdateWorker.class.getName()) ) {
			ret = CRLUpdateWorkerType.NAME;
		}
        if ( (cp != null) && cp.equals(CRLDownloadWorker.class.getName()) ) {
            ret = CRLDownloadWorkerType.NAME;
        }
        if (ret==null) {
            ret = CustomWorkerType.NAME;
        }
		return ret;
	}

	/** Help method used to edit data in the RenewCAWorkerType. */
	public RenewCAWorkerType getRenewType(){
		String name = RenewCAWorkerType.NAME;
		return (RenewCAWorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(name);
	}

	/** Help method to edit data in the publish queue worker type */
	public PublishQueueWorkerType getPublishWorkerType() {
		return (PublishQueueWorkerType)serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(PublishQueueWorkerType.NAME);
	}
    
	/** Help method used to edit data in the CRLDownloadWorkerType. */
    public CRLDownloadWorkerType getCrlDownloadWorkerType() {
        String name = CRLDownloadWorkerType.NAME;
        return (CRLDownloadWorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(name);
    }

	/** Help method used to edit data in the custom interval type. */
	public PeriodicalIntervalType getPeriodicalIntervalType(){
		return (PeriodicalIntervalType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(PeriodicalIntervalType.NAME);
	}

	public void changeInterval(ValueChangeEvent e){
		String newName = (String) e.getNewValue();		
        WorkerType workerType = serviceConfigurationView.getWorkerType();
		if(workerType.getCompatibleIntervalTypeNames().contains(newName)){
			IntervalType newIntervalType = (IntervalType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(newName);
			serviceConfigurationView.setIntervalType(newIntervalType);
			serviceConfigurationView.setSelectedInterval(newName);
		}
	}
	
	public void changeAction(ValueChangeEvent e){
		String newName = (String) e.getNewValue();		
        WorkerType workerType = serviceConfigurationView.getWorkerType();
		if(workerType.getCompatibleActionTypeNames().contains(newName)){
		  ActionType newActionType = (ActionType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(newName);
		  serviceConfigurationView.setActionType(newActionType);
		  serviceConfigurationView.setSelectedAction(newName);		  
		}
	}
	
	/** Returns the list of available CAs, only including the actually present CAs.
     * 
     * @return List<javax.faces.model.SelectItem>(String, String) of CA id's (as String) and CA names
     */
    public List<SelectItem> getAvailableCAs() {
        List<SelectItem> availableCANames = new ArrayList<SelectItem>();
        for (Integer caid : ejb.getCaSession().getAuthorizedCaIds(getAdmin())) {
            try {
                availableCANames.add(new SelectItem(caid.toString(), ejb.getCaSession().getCAInfo(getAdmin(), caid).getName()));
            } catch (CADoesntExistsException e) {
                log.debug("CA does not exist: " + caid);
            } catch (AuthorizationDeniedException e) {
                log.debug("Not authorized to CA: " + caid);
            }
        }
        return availableCANames;
    }
	/** Returns the list of available CAs, also including the special option 'Any CA'.
	 * 
	 * @return List<javax.faces.model.SelectItem>(String, String) of CA id's (as String) and CA names
	 */
    public List<SelectItem> getAvailableCAsWithAnyOption() {
        List<SelectItem> availableCANames = new ArrayList<SelectItem>();
        String caname = (String)EjbcaJSFHelper.getBean().getText().get("ANYCA");
        availableCANames.add(new SelectItem(String.valueOf(SecConst.ALLCAS), caname));
        availableCANames.addAll(getAvailableCAs());
        return availableCANames;
    }

    /** Returns the list of available external X509 CAs, also including the special option 'Any CA'.
     * 
     * @return List<javax.faces.model.SelectItem>(String, String) of CA id's (as String) and CA names
     */
    public List<SelectItem> getAvailableExternalX509CAsWithAnyOption() {
        final List<SelectItem> availableCANames = new ArrayList<SelectItem>();
        final String caname = EjbcaJSFHelper.getBean().getText().get("ANYCA");
        availableCANames.add(new SelectItem(String.valueOf(SecConst.ALLCAS), caname));
        for (final Integer caid : ejb.getCaSession().getAuthorizedCaIds(getAdmin())) {
            try {
                CAInfo caInfo = ejb.getCaSession().getCAInfo(getAdmin(), caid);
                availableCANames.add(new SelectItem(caid.toString(), ejb.getCaSession().getCAInfo(getAdmin(), caid).getName(), null, caInfo.getCAType()!=CAInfo.CATYPE_X509 || caInfo.getStatus()!=CAConstants.CA_EXTERNAL));
            } catch (CADoesntExistsException e) {
                log.debug("CA does not exist: " + caid);
            } catch (AuthorizationDeniedException e) {
                log.debug("Not authorized to CA: " + caid);
            }
        }
        return availableCANames;
    }    
    
    /**
     * 
     * 
     * @return a {@link List} of {@link SelectItem}s containing the ID's and names of all ENDENTITY, ROOTCA and SUBCA 
     * (and HARDTOKEN if available) certificate profiles current admin is authorized to.
     */
    public Collection<SelectItem> getCertificateProfiles() {
        TreeMap<String, SelectItem> certificateProfiles = new TreeMap<String, SelectItem>();
         
        final List<Integer> certificateProfileTypes = new ArrayList<>();
        certificateProfileTypes.add(CertificateConstants.CERTTYPE_ENDENTITY);
        if (isAuthorizedTo(StandardRules.ROLE_ROOT.resource())) {
            //Only root users may use CA profiles
            certificateProfileTypes.add(CertificateConstants.CERTTYPE_ROOTCA);
            certificateProfileTypes.add(CertificateConstants.CERTTYPE_SUBCA);
        }
        
        if (getEjbcaWebBean().getGlobalConfiguration().getIssueHardwareTokens()) {
            certificateProfileTypes.add(CertificateConstants.CERTTYPE_HARDTOKEN);
        }
             
        for (Integer certificateProfileType : certificateProfileTypes) {
            Collection<Integer> profiles = certificateProfileSession.getAuthorizedCertificateProfileIds(getAdmin(), certificateProfileType);
            for (Integer certificateProfile : profiles) {
                String profileName = certificateProfileSession.getCertificateProfileName(
                        certificateProfile);
                certificateProfiles.put(profileName.toLowerCase(), new SelectItem(certificateProfile.toString(), profileName));
            }
        }        
        return certificateProfiles.values();
    }


	public List<SelectItem> getAvailablePublishers(){
		List<SelectItem> availablePublisherNames = new ArrayList<SelectItem>();
        for (int next : ejb.getCaAdminSession().getAuthorizedPublisherIds(getAdmin())) {
            // Display it in the list as "PublisherName (publisherId)" with publisherId as the value sent
            availablePublisherNames.add(new SelectItem(String.valueOf(next), ejb.getPublisherSession().getPublisherName(next) + " (" + next + ")"));
        }
		return availablePublisherNames;		
	}
	
	/** Return type used by getManualCustomActionItems */
    public static class ManualCustomItems {
        private final List<SelectItem> workers = new ArrayList<SelectItem>();
        private final List<SelectItem> intervals = new ArrayList<SelectItem>();
        private final List<SelectItem> actions = new ArrayList<SelectItem>();
        public List<SelectItem> getWorkers() { return workers; }
        public List<SelectItem> getIntervals() { return intervals; }
        public List<SelectItem> getActions() { return actions; }
    }
    
    public ManualCustomItems getManualCustomItems() {
        ManualCustomItems manual = new ManualCustomItems();
        final String workerClass = getCustomWorkerType().getAutoClassPath();
        if (!StringUtils.isEmpty(workerClass) && !CustomLoader.getCustomClasses(IWorker.class).contains(workerClass)) {
            manual.getWorkers().add(new SelectItem(workerClass, workerClass+"*"));
        }
        final String intervalClass = getCustomIntervalType().getAutoClassPath();
        if (!StringUtils.isEmpty(intervalClass) && !CustomLoader.getCustomClasses(IInterval.class).contains(intervalClass)) {
            manual.getIntervals().add(new SelectItem(intervalClass, intervalClass+"*"));
        }
        final String actionClass = getCustomActionType().getAutoClassPath();
        if (!StringUtils.isEmpty(actionClass) && !CustomLoader.getCustomClasses(IAction.class).contains(actionClass)) {
            manual.getActions().add(new SelectItem(actionClass, actionClass+"*"));
        }
        return manual;
    }
}
