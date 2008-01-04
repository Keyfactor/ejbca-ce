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

package org.ejbca.core.ejb.log;

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.Properties;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.ILogDevice;
import org.ejbca.core.model.log.ILogExporter;
import org.ejbca.core.model.log.Log4jLogDevice;
import org.ejbca.core.model.log.Log4jLogDeviceFactory;
import org.ejbca.core.model.log.LogConfiguration;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.log.OldLogDevice;
import org.ejbca.core.model.log.OldLogDeviceFactory;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.util.CertTools;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;


/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 *
 * @ejb.bean
 *   display-name="LogSessionSB"
 *   name="LogSession"
 *   jndi-name="LogSession"
 *   local-jndi-name="LogSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry
 * name="DataSource"
 * type="java.lang.String"
 * value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 * @ejb.env-entry
 *   description="Defines the JNDI name of the mail service used"
 *   name="MailJNDIName"
 *   type="java.lang.String"
 *   value="${mail.jndi-name}"
 *   
 * @ejb.ejb-external-ref
 *   description="The Log Entry Data entity bean"
 *   view-type="local"
 *   ref-name="ejb/LogEntryDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.log.LogEntryDataLocalHome"
 *   business="org.ejbca.core.ejb.log.LogEntryDataLocal"
 *   link="LogEntryData"
 *
 * @ejb.ejb-external-ref
 *   description="The Log Configuration Data Entity bean"
 *   view-type="local"
 *   ref-name="ejb/LogConfigurationDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.log.LogConfigurationDataLocalHome"
 *   business="org.ejbca.core.ejb.log.LogConfigurationDataLocal"
 *   link="LogConfigurationData"
 *
 * @ejb.ejb-external-ref
 *   description="The table protection session bean"
 *   view-type="local"
 *   ref-name="ejb/TableProtectSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.protect.TableProtectSessionLocalHome"
 *   business="org.ejbca.core.ejb.protect.TableProtectSessionLocal"
 *   link="TableProtectSession"
 *   
 * @ejb.ejb-external-ref description="The Sign Session Bean"
 *   view-type="local"
 *   ref-name="ejb/RSASignSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.sign.ISignSessionLocal"
 *   link="RSASignSession"
 *   
 * @ejb.ejb-external-ref
 *   description="The Authorization session bean"
 *   view-type="local"
 *   ref-name="ejb/AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *   
 * @ejb.ejb-external-ref
 *   description="The CA Admin Session"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *   
 * @ejb.ejb-external-ref
 *   description="ProtectedLogSessionBean"
 *   view-type="local"
 *   ref-name="ejb/ProtectedLogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.IProtectedLogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.IProtectedLogSessionLocal"
 *   link="ProtectedLogSession"
 *   
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.log.ILogSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   remote-class="org.ejbca.core.ejb.log.ILogSessionRemote"
 *
 * @jonas.bean
 *   ejb-name="LogSession"
 *
 * @version $Id: LocalLogSessionBean.java,v 1.24 2008-01-04 08:55:20 jeklund Exp $
 */
public class LocalLogSessionBean extends BaseSessionBean {

	/** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /** The local interface of  authorization session bean */
	private IAuthorizationSessionLocal authorizationsession;
    /** The home interface of  LogConfigurationData entity bean */
    private LogConfigurationDataLocalHome logconfigurationhome;

    /** Collection of available log devices, i.e Log4j etc */
    private ArrayList logdevices;

    /**
     * Default create for SessionBean without any creation Arguments.
     */
    public void ejbCreate() {
        try {
            logconfigurationhome = (LogConfigurationDataLocalHome) ServiceLocator.getInstance().getLocalHome(LogConfigurationDataLocalHome.COMP_NAME);
            // Setup Connection to signing devices.
            logdevices = new ArrayList();
            // Load logging properties dynamically as interal resource
            Properties logProperties = new Properties();
            String logDevicesString = null;
            InputStream logPropertiesInputStream = this.getClass().getResourceAsStream("/conf/log.properties");
            if (logPropertiesInputStream != null) {
                logProperties.load(logPropertiesInputStream);
                logDevicesString = logProperties.getProperty("usedLogDevices");
            }
            // Set some defaults if no properties were found
            if (logDevicesString == null) {
            	logDevicesString = Log4jLogDevice.DEFAULT_DEVICE_NAME+";"+OldLogDevice.DEFAULT_DEVICE_NAME;
            	logProperties.setProperty(Log4jLogDevice.DEFAULT_DEVICE_NAME, Log4jLogDeviceFactory.class.getName() + ";");
            	logProperties.setProperty(OldLogDevice.DEFAULT_DEVICE_NAME, OldLogDeviceFactory.class.getName() + ";");
            }
            if (logDevicesString != null) {
                String[] logDevices = logDevicesString.split(";");
	            for (int i = 0; i < logDevices.length; i++) {
	            	String logDeviceString = logProperties.getProperty(logDevices[i]);
	            	if (logDeviceString == null) {
	            		continue;
	            	}
	            	String[] logDeviceComponents = logDeviceString.split(";");
	            	// Load properties
	            	Properties properties = new Properties();
	                if (logDeviceComponents.length > 1 && !(logDeviceComponents[1] == null || logDeviceComponents[1].trim().equals(""))) {
	                	InputStream is = null;
	                	try {
	                		is = this.getClass().getResourceAsStream("/conf/" + logDeviceComponents[1].trim());
	                		// Ignore missing config files
	                		if (is != null) {
		                		properties.load(is);
	                		}
	                	} finally {
	                		if (is != null) is.close();
	                	}
	                }
	            	properties.setProperty(ILogDevice.PROPERTY_DEVICENAME, logDevices[i]);
	            	// Create log class
	                if (logDeviceComponents.length > 0) {
		            	Class implClass = Class.forName(logDeviceComponents[0].trim());
		                Object fact = implClass.newInstance();
		                Class[] paramTypes = new Class[] {Properties.class};
		                Method method = implClass.getMethod("makeInstance", paramTypes);
		                Object[] params = new Object[1];
	                    params[0] = properties;
		                logdevices.add(method.invoke(fact, params));
	                }
	            }
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }
    
    public void ejbRemove() {
        Iterator i = logdevices.iterator();
        while (i.hasNext()) {
            ILogDevice dev = (ILogDevice) i.next();
            dev.destructor();
        }
    }

    /**
     * @ejb.interface-method
     */
    public Properties getProperties(Class logDeviceClass) {
        Iterator i = logdevices.iterator();
        while (i.hasNext()) {
            ILogDevice dev = (ILogDevice) i.next();
            if (dev.getClass().equals(logDeviceClass)) {
            	return dev.getProperties();
            }
        }
        return null;
    }
    
    /**
     * @ejb.interface-method view-type="both"
     */
    public Collection getAvailableLogDevices() {
    	ArrayList ret = new ArrayList();
    	Iterator i = logdevices.iterator();
    	while (i.hasNext()) {
    		ret.add( ((ILogDevice) i.next()).getDeviceName() );
    	}
    	Collections.reverse(ret);
    	return ret;
    }
    
    private Collection testDeviceBackup = new ArrayList();
    private Properties testDeviceProperties = null;

    /**
     * Replace existing devices with new ones. Used for testing.
     * @ejb.interface-method view-type="both"
     */
    public void setTestDevice(Class implClass, Properties properties) {
    	try {
    		Object fact = implClass.newInstance();
    		Class[] paramTypes = new Class[] {Properties.class};
    		Method method = implClass.getMethod("makeInstance", paramTypes);
    		Object[] params = new Object[1];
    		params[0] = properties;
            ILogDevice dev = (ILogDevice) method.invoke(fact, params);
        	Iterator i = logdevices.iterator();
        	ILogDevice dev2 = null;
        	while (i.hasNext()) {
        		dev2 = (ILogDevice) i.next();
        		if (dev2.getDeviceName().equals(dev.getDeviceName())) {
        			break;
        		}
        	}
        	if (testDeviceBackup.size() == 0) {
            	testDeviceBackup.addAll(logdevices);
    			testDeviceProperties = dev2.getProperties();
        	}
            dev.resetDevice(properties);
        	logdevices.clear();
    		logdevices.add(dev);
    	} catch (Exception e) {
			log.error(e);
		}
    }
    
    /**
     * Replace test device with original ones. Used for testing.
     * @ejb.interface-method view-type="both"
     */
    public void restoreTestDevice() {
        ILogDevice dev = (ILogDevice) logdevices.iterator().next();
    	Iterator i = testDeviceBackup.iterator();
    	while (i.hasNext()) {
    		ILogDevice dev2 = (ILogDevice) i.next();
    		if (dev2.getDeviceName().equals(dev.getDeviceName())) {
    			dev.resetDevice(testDeviceProperties);
    		}
    	}
    	if (testDeviceBackup.size() != 0) {
        	logdevices.clear();
        	logdevices.addAll(testDeviceBackup);
        	testDeviceBackup.clear();
    	}
    }

    /**
     * Session beans main function. Takes care of the logging functionality.
     *
     * @param admin the administrator performing the event.
     * @param time the time the event occured.
     * @param username the name of the user involved or null if no user is involved.
     * @param certificate the certificate involved in the event or null if no certificate is involved.
     * @param event id of the event, should be one of the org.ejbca.core.model.log.LogConstants.EVENT_ constants.
     * @param comment comment of the event.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public void log(Admin admin, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment) {
        doLog(admin, caid, module, time, username, certificate, event, comment, null);
    } // log

    /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of given certificate.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public void log(Admin admin, X509Certificate caid, int module, Date time, String username, X509Certificate certificate, int event, String comment) {
        log(admin, CertTools.getIssuerDN(caid).hashCode(), module, time, username, certificate, event, comment);
    } // log

    /**
     * Overloaded function that also logs an exception
     * See function above for more documentation.
     *
     * @param exception the exception that has occured
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     *
     */
    public void log(Admin admin, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception) {
        doLog(admin, caid, module, time, username, certificate, event, comment, exception);
    }

    /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of given certificate.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public void log(Admin admin, X509Certificate caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception) {
        log(admin, CertTools.getIssuerDN(caid).hashCode(), module, time, username, certificate, event, comment, exception);
    } // log

    /**
     * Internal implementation for logging. Does not allow Exceptions to propagate outside the logging functionality.
     * 
     * @ejb.transaction type="Supports"
     */
    private void doLog(Admin admin, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception ex) {
        try {
	        boolean authorized = true;
	        if(event == LogConstants.EVENT_INFO_CUSTOMLOG || event == LogConstants.EVENT_ERROR_CUSTOMLOG){
	           try{
	        	getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_LOG_CUSTOM_EVENTS);
	           }catch(AuthorizationDeniedException e){
	        	   String msg = intres.getLocalizedMessage("log.notauthtocustomlog");
	        	   doSyncronizedLog(admin,caid,LogConstants.MODULE_LOG,new Date(),username, null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,null);
	        	   authorized = false;
	           }
	        }
	        if (authorized) {
	            doSyncronizedLog(admin, caid, module, time, username, certificate, event, comment, ex);
	        }
        } catch (Throwable e) {
	        String msg = intres.getLocalizedMessage("log.errormissingentry");            	
	        log.error(msg, e);
        }
    }
    /**
     * Internal implementation for logging
     *
     * @ejb.transaction type="RequiresNew"
     */
    private void doSyncronizedLog(Admin admin, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception ex) {
        final LogConfiguration config = loadLogConfiguration(caid);
        Iterator i = logdevices.iterator();
        while (i.hasNext()) {
    		ILogDevice dev = (ILogDevice) i.next();
        	if (!dev.getAllowConfigurableEvents() || config.logEvent(event)) {
        		dev.log(admin, caid, module, time, username, certificate, event, comment, ex);
        	}
        }
    }

    /**
     * Method to export log records according to a customized query on the log db data. The parameter query should be a legal Query object.
     *
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @param viewlogprivileges is a sql query string returned by a LogAuthorization object.
     * @param logexporter is the obbject that converts the result set into the desired log format 
     * @return an exported byte array. Maximum number of exported entries is defined i LogConstants.MAXIMUM_QUERY_ROWCOUNT, returns null if there is nothing to export
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @throws ExtendedCAServiceNotActiveException 
     * @throws IllegalExtendedCAServiceRequestException 
     * @throws ExtendedCAServiceRequestException 
     * @throws CADoesntExistsException 
     * @see org.ejbca.util.query.Query
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     *
     */
    public byte[] export(String deviceName, Admin admin, Query query, String viewlogprivileges, String capriviledges, ILogExporter logexporter) throws IllegalQueryException, CADoesntExistsException, ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException {
    	byte[] result = null;
    	Iterator i = logdevices.iterator();
        while (i.hasNext()) {
            ILogDevice dev = (ILogDevice) i.next();
            if (dev.getDeviceName().equalsIgnoreCase(deviceName)) {
            	result = dev.export(admin, query, viewlogprivileges, capriviledges, logexporter);
            	break;
            }
        }
		return result;
    }
    
    /**
     * Method to execute a customized query on the log db data. The parameter query should be a legal Query object.
     *
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @param viewlogprivileges is a sql query string returned by a LogAuthorization object.
     * @return a collection of LogEntry. Maximum size of Collection is defined i LogConstants.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @see org.ejbca.util.query.Query
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public Collection query(String deviceName, Query query, String viewlogprivileges, String capriviledges) throws IllegalQueryException {
        debug(">query()");
    	Collection result = null;
    	Iterator i = logdevices.iterator();
        while (i.hasNext()) {
            ILogDevice dev = (ILogDevice) i.next();
            if (dev.getDeviceName().equalsIgnoreCase(deviceName)) {
                result = dev.query(query, viewlogprivileges, capriviledges);
                break;
            }
        }
		return result;
    } // query

    /**
     * Loads the log configuration from the database.
     *
     * @return the logconfiguration
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     *
     */
    public LogConfiguration loadLogConfiguration(int caid) {
        // Check if log configuration exists, else create one.
        LogConfiguration logconfiguration = null;
        LogConfigurationDataLocal logconfigdata = null;
        try {
            logconfigdata = logconfigurationhome.findByPrimaryKey(new Integer(caid));
            logconfiguration = logconfigdata.loadLogConfiguration();
        } catch (FinderException e) {
            log.debug("Can't find log configuration during load (caid="+caid+"), trying to create new: ", e);
            try {
                logconfiguration = new LogConfiguration();
                logconfigdata = logconfigurationhome.create(new Integer(caid), logconfiguration);
            } catch (CreateException f) {
                String msg = intres.getLocalizedMessage("log.errorcreateconf", new Integer(caid));            	
                log.error(msg, f);
                throw new EJBException(f);
            }
        }

        return logconfiguration;
    } // loadLogConfiguration

    /**
     * Saves the log configuration to the database.
     *
     * @param logconfiguration the logconfiguration to save.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     *
     */
    public void saveLogConfiguration(Admin admin, int caid, LogConfiguration logconfiguration) {
        try {
            try {
                (logconfigurationhome.findByPrimaryKey(new Integer(caid))).saveLogConfiguration(logconfiguration);
                log(admin, caid, LogConstants.MODULE_LOG, new Date(), null, null, LogConstants.EVENT_INFO_EDITLOGCONFIGURATION, "");
            } catch (FinderException e) {
                String msg = intres.getLocalizedMessage("log.createconf", new Integer(caid));            	
                log.info(msg);
                logconfigurationhome.create(new Integer(caid), logconfiguration);
                log(admin, caid, LogConstants.MODULE_LOG, new Date(), null, null, LogConstants.EVENT_INFO_EDITLOGCONFIGURATION, "");
            }
        } catch (Exception e) {
            log(admin, caid, LogConstants.MODULE_LOG, new Date(), null, null, LogConstants.EVENT_ERROR_EDITLOGCONFIGURATION, "");
            throw new EJBException(e);
        }
    } // saveLogConfiguration


    /**
     * Gets connection to authorization session bean
     *
     * @return IAuthorizationSessionLocal
     */
    private IAuthorizationSessionLocal getAuthorizationSession() {
        if (authorizationsession == null) {
            try {
                IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) getLocator().getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
                authorizationsession = authorizationsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return authorizationsession;
    } //getAuthorizationSession

} // LocalLogSessionBean
