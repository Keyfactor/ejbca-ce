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
package org.ejbca.ui.web.admin.cainterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.configuration.InformationMemory;

/**
 * @author Tham Wickenberg
 * @version $Id$
 */
public class CAActivationMBean extends BaseManagedBean implements Serializable {

	private static final Logger log = Logger.getLogger(CAActivationMBean.class);

	private static final long serialVersionUID = -2660384552215596717L;

	private EjbcaJSFHelper jsfHelper;
	private EjbcaWebBean webBean;
	private CADataHandler cadatahandler;
	private CAInterfaceBean caBean;
	private String authenticationcode;
	private List caInfoList;
	private Admin administrator;
	private ICertificateStoreSessionLocal      certificatesession;
	private ICAAdminSessionLocal               caadminsession;
	private IAuthorizationSessionLocal         authorizationsession;
	private IUserAdminSessionLocal             adminsession;
	private IRaAdminSessionLocal               raadminsession;
	private ISignSessionLocal                  signsession;
	private InformationMemory                  informationmemory;
	public static final String MAKEOFFLINE = "makeoffline";
	public static final String ACTIVATE    = "activate";
	public static final String KEEPCURRENT = "keepcurrent";

	public CAActivationMBean () {
		jsfHelper = EjbcaJSFHelper.getBean();
		webBean = jsfHelper.getEjbcaWebBean();
		new ViewCAInfoJSPHelper();
		caBean = new CAInterfaceBean();
		try {
			caBean.initialize(webBean.getAdminObject(), webBean);
		} catch (Exception e) {
			log.error("Error initializing bean: ", e);
		}
		try {
			administrator = webBean.getAdminObject();
			ServiceLocator locator = ServiceLocator.getInstance();
			ICertificateStoreSessionLocalHome certificatesessionhome = (ICertificateStoreSessionLocalHome) locator.getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
			certificatesession = certificatesessionhome.create();

			ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) locator.getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
			caadminsession = caadminsessionhome.create();

			IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) locator.getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
			authorizationsession = authorizationsessionhome.create();

			IUserAdminSessionLocalHome adminsessionhome = (IUserAdminSessionLocalHome) locator.getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
			adminsession = adminsessionhome.create();

			IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) locator.getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
			raadminsession = raadminsessionhome.create();               

			ISignSessionLocalHome home = (ISignSessionLocalHome)locator.getLocalHome(ISignSessionLocalHome.COMP_NAME );
			signsession = home.create();

			IHardTokenSessionLocalHome hardtokensessionhome = (IHardTokenSessionLocalHome)locator.getLocalHome(IHardTokenSessionLocalHome.COMP_NAME);
			hardtokensessionhome.create();               

			IPublisherSessionLocalHome publishersessionhome = (IPublisherSessionLocalHome) locator.getLocalHome(IPublisherSessionLocalHome.COMP_NAME);
			publishersessionhome.create();               

			this.informationmemory = webBean.getInformationMemory();

			new CertificateProfileDataHandler(administrator, certificatesession, authorizationsession, caadminsession, informationmemory);
			cadatahandler = new CADataHandler(administrator, caadminsession, adminsession, raadminsession, certificatesession, authorizationsession, signsession, webBean);
			caInfoList = new ArrayList();
			initializeWrappers();
		} catch (Exception e){
			log.error("Error initializing bean: ", e);
		}
	}

	/** Returns list of authorized CAs
	 * 
	 * @return List of CAWrapper
	 */
	public List getAuthorizedCAWrappers() {
		initializeWrappers();
		Iterator it = caInfoList.iterator();
		while ( it.hasNext() ) {
			CAWrapper temp = (CAWrapper) it.next();
			try {
				temp.setCAInfo(caBean.getCAInfo(temp.getID()).getCAInfo());
			} catch (Exception e) {
				log.error(e);
			}
		}
		return caInfoList;
	}

	public void initializeWrappers() {
		Collection idList = webBean.getAuthorizedCAIds();
		Iterator it = idList.iterator();
		while ( it.hasNext() ) {
			Integer caid = (Integer) it.next();
			boolean inList = false;
			Iterator tempIt = caInfoList.iterator();
			while (tempIt.hasNext()) {
				CAWrapper wrapper = (CAWrapper)tempIt.next();
				if (wrapper.getID() == caid.intValue() ) {
					inList = true;
				}
			}
			if (!inList) {
				try {
					caInfoList.add(new CAWrapper(caBean.getCAInfo( caid.intValue()).getCAInfo(), webBean, this));
				} catch (Exception e) {
					log.error(e);
				}
			}
		}
	}

	public void setAuthenticationCode(String authenticationcode) {
		this.authenticationcode = authenticationcode;
	}

	public String getAuthenticationCode() {
		return "";
	}

	public CAInfo activateCAToken(int caid ) throws CATokenAuthenticationFailedException, CATokenOfflineException, AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, Exception {
		cadatahandler.activateCAToken(caid, authenticationcode);
		log.debug("Successfully activated token");
		return caBean.getCAInfo(caid).getCAInfo();
	}

	public CAInfo deactivateCAToken(int caid) throws AuthorizationDeniedException, EjbcaException, Exception {
		cadatahandler.deactivateCAToken(caid);
		log.debug("Successfully de-activated token");
		return caBean.getCAInfo(caid).getCAInfo();
	}

	/** Updates the IncludeInChealthCheck flag in the database for the CA
	 */
	public CAInfo updateMonitored(int caid, boolean monitored) throws Exception {
		CAInfoView cv = caBean.getCAInfo(caid);
		if (cv != null) {
			CAInfo cainfo = cv.getCAInfo();
			cainfo.setincludeInHealthCheck(monitored);
			cadatahandler.editCA(cainfo);
			return cainfo;			
		} else {
			log.debug("No CA with id: "+caid);
		}
		return null;
	}
	
	public void apply() {
		log.trace(">apply");
		List list = caInfoList;
		for (Iterator iterator = list.iterator(); iterator.hasNext();) {
			CAWrapper wrapper = (CAWrapper) iterator.next();
			try {
				String option = wrapper.getActivateOption();
				if (option.equals(CAActivationMBean.ACTIVATE)) {
					wrapper.activateCAToken();
				}
				if (option.equals(CAActivationMBean.MAKEOFFLINE)) { 
					wrapper.deactivateCAToken();
				}
				if (option.equals(CAActivationMBean.KEEPCURRENT)) {
					wrapper.setCAActivationMessage("");			
				}
				// Update the monitored flag in the DB if it changed
				CAInfoView cv = caBean.getCAInfo(wrapper.getID());
				if (cv != null) {
					CAInfo cainfo = cv.getCAInfo();
					if (wrapper.getMonitored() != cainfo.getIncludeInHealthCheck()) {
						wrapper.updateMonitored();
					}					
				} else {
					log.debug("No CA with id: "+wrapper.getID());
				}
			} catch (Exception e) {
				log.error(e);
			}			
		}
		log.trace("<apply");
	}

	public String getMakeoffline() {
		return MAKEOFFLINE;
	}
	public String getActivate() {
		return ACTIVATE;
	}
	public String getKeepcurrent() {
		return KEEPCURRENT;
	}
	
	public List getHasMessages() {
		log.trace(">getHasMessages");
		List list = caInfoList;
		List hasMessages = new ArrayList();
		for (Iterator iterator = list.iterator(); iterator.hasNext();) {
			CAWrapper wrapper = (CAWrapper) iterator.next();
			String msg = wrapper.getCAActivationMessage();
			if ( (msg != null) && (!msg.equals("")) ) {
				hasMessages.add(wrapper);
			}			
		}
		log.trace("<getHasMessages");
		return hasMessages;
	}
}
