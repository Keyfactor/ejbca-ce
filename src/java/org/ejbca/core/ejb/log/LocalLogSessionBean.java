/*************************************************************************
 *                                                                       *
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
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

import java.lang.reflect.Method;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.ILogDevice;
import org.ejbca.core.model.log.ILogExporter;
import org.ejbca.core.model.log.LogConfiguration;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.log.OldLogDevice;
import org.ejbca.util.CertTools;
import org.ejbca.util.ObjectCache;
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
 *   description="The CA Admin Session"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
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
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "LogSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class LocalLogSessionBean implements LogSessionLocal, LogSessionRemote {

    private static final Logger log = Logger.getLogger(LocalLogSessionBean.class);
    
	/** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /** Cache for log configuration data with default cache time of 5 seconds.
     * 5 seconds is enough to not limit performance in high performance environments, but low enough so that 
     * changes to configuration is visible almost immediately.
     */
    private static volatile ObjectCache logConfCache = new ObjectCache(EjbcaConfiguration.getCacheLogConfigurationTime());

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;
    
    @EJB
    private OldLogSessionLocal oldLogSession;	// Injected into OldLogDevice (if used).

    /** Collection of available log devices, i.e Log4j etc */
    private ArrayList<ILogDevice> logdevices;

    @PostConstruct
    public void ejbCreate() {
        try {
            // Setup Connection to signing devices.
            logdevices = new ArrayList<ILogDevice>();
            // Load logging properties dynamically as internal resource
            Map<String,String> logDeviceMap = org.ejbca.config.LogConfiguration.getUsedLogDevices();
            Iterator<String> i = logDeviceMap.keySet().iterator();
            while (i.hasNext()) {
            	String deviceName = i.next();
            	// Create log class
            	Class implClass = Class.forName(logDeviceMap.get(deviceName));
                Object fact = implClass.newInstance();
                Class[] paramTypes = new Class[] {String.class};
                Method method = implClass.getMethod("makeInstance", paramTypes);
                Object[] params = new Object[1];
                params[0] = deviceName;
                logdevices.add((ILogDevice) method.invoke(fact, params));
            }
        	// Workaround to be able to avoid local ENC lookup and use injection instead.
            for (ILogDevice logDevice : logdevices) {
            	if (logDevice instanceof OldLogDevice) {
            		((OldLogDevice)logDevice).setOldLogSessionInterface(oldLogSession);
            	}
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }
    
    /**
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public Collection<String> getAvailableLogDevices() {
    	ArrayList<String> ret = new ArrayList<String>();
    	Iterator<ILogDevice> i = logdevices.iterator();
    	while (i.hasNext()) {
    		ret.add( i.next().getDeviceName() );
    	}
    	Collections.reverse(ret);
    	return ret;
    }

    /**
     * Session beans main function. Takes care of the logging functionality.
     *
     * @param admin the administrator performing the event.
     * @param time the time the event occurred.
     * @param username the name of the user involved or null if no user is involved.
     * @param certificate the certificate involved in the event or null if no certificate is involved.
     * @param event id of the event, should be one of the org.ejbca.core.model.log.LogConstants.EVENT_ constants.
     * @param comment comment of the event.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public void log(Admin admin, int caid, int module, Date time, String username, Certificate certificate, int event, String comment) {
        doLog(admin, caid, module, time, username, certificate, event, comment, null);
    }

    /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of given certificate.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public void log(Admin admin, Certificate caid, int module, Date time, String username, Certificate certificate, int event, String comment) {
        doLog(admin, CertTools.getIssuerDN(caid).hashCode(), module, time, username, certificate, event, comment, null);
    }

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
    public void log(Admin admin, int caid, int module, Date time, String username, Certificate certificate, int event, String comment, Exception exception) {
        doLog(admin, caid, module, time, username, certificate, event, comment, exception);
    }

    /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of given certificate.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public void log(Admin admin, Certificate caid, int module, Date time, String username, Certificate certificate, int event, String comment, Exception exception) {
        doLog(admin, CertTools.getIssuerDN(caid).hashCode(), module, time, username, certificate, event, comment, exception);
    }

    /**
     * Internal implementation for logging. Does not allow Exceptions to propagate outside the logging functionality.
     */
    private void doLog(Admin admin, int caid, int module, Date time, String username, Certificate certificate, int event, String comment, Exception ex) {
    	Iterator<ILogDevice> i = logdevices.iterator();
    	while (i.hasNext()) {
    		ILogDevice dev = i.next();
    		try {
    	    	final LogConfiguration config = loadLogConfiguration(caid);
    	    	if (!dev.getAllowConfigurableEvents() || config.logEvent(event)) {
    	    		dev.log(admin, caid, module, time, username, certificate, event, comment, ex);
    	    	}
    		} catch (Throwable e) {
            	log.error(intres.getLocalizedMessage("log.error.logdropped",admin.getAdminType()+" "+admin.getAdminData()+" "
            			+caid+" "+" "+module+" "+" "+time+" "+username+" "+(certificate==null?"null":CertTools.getSerialNumberAsString(certificate)+" "
               			+CertTools.getIssuerDN(certificate))+" "+event+" "+comment+" "+ex));
    			String msg = intres.getLocalizedMessage("log.errormissingentry");
    			log.error(msg, e);
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
     * @throws Exception differs depending on the ILogExporter implementation
     * @see org.ejbca.util.query.Query
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     *
     */
    public byte[] export(String deviceName, Admin admin, Query query, String viewlogprivileges, String capriviledges, ILogExporter logexporter, int maxResults) throws IllegalQueryException, Exception {
    	byte[] result = null;
    	Iterator<ILogDevice> i = logdevices.iterator();
        while (i.hasNext()) {
            ILogDevice dev = i.next();
            if (dev.getDeviceName().equalsIgnoreCase(deviceName)) {
            	result = dev.export(admin, query, viewlogprivileges, capriviledges, logexporter, maxResults);
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
    public Collection<LogEntry> query(String deviceName, Query query, String viewlogprivileges, String capriviledges, int maxResults) throws IllegalQueryException {
        log.trace(">query()");
    	Collection<LogEntry> result = null;
    	Iterator<ILogDevice> i = logdevices.iterator();
        while (i.hasNext()) {
            ILogDevice dev = i.next();
            if (dev.getDeviceName().equalsIgnoreCase(deviceName)) {
                result = dev.query(query, viewlogprivileges, capriviledges, maxResults);
                break;
            }
        }
		return result;
    }

    /**
     * Loads the log configuration from the database.
     *
     * @return the logconfiguration
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     *
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public LogConfiguration loadLogConfiguration(int caid) {
        // Check if log configuration exists, else create one.
        LogConfiguration ret = null; 
    	Object o = logConfCache.get(Integer.valueOf(caid));
    	if (o == null) {
    		LogConfigurationData logconfigdata = LogConfigurationData.findByPK(entityManager, Integer.valueOf(caid));
    		if (logconfigdata != null) {
    			ret = logconfigdata.loadLogConfiguration();
    		} else {
    			log.debug("Can't find log configuration during load (caid="+caid+"), trying to create new.");
    			try {
    				ret = new LogConfiguration();
    				entityManager.persist(new LogConfigurationData(new Integer(caid), ret));
    			} catch (Exception f) {
    				String msg = intres.getLocalizedMessage("log.errorcreateconf", new Integer(caid));            	
    				log.error(msg, f);
    				throw new EJBException(f);
    			}
    		}
    		if (ret != null) {
    			logConfCache.put(Integer.valueOf(caid), ret);
    		}
    	} else {
    		ret = (LogConfiguration)o;
    	}
        return ret;
    }

    /**
     * Saves the log configuration to the database.
     *
     * @param logconfiguration the logconfiguration to save.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     *
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void saveLogConfiguration(Admin admin, int caid, LogConfiguration logconfiguration) {
    	internalSaveLogConfigurationNoFlushCache(admin, caid, logconfiguration);
        // Update cache
		logConfCache.put(Integer.valueOf(caid), logconfiguration);    	
    }
    
    /** Do not use, use saveLogConfiguration instead.
     * Used internally for testing only. Updates configuration without flushing caches.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void internalSaveLogConfigurationNoFlushCache(Admin admin, int caid, LogConfiguration logconfiguration) {
        try {
        	log(admin, caid, LogConstants.MODULE_LOG, new Date(), null, null, LogConstants.EVENT_INFO_EDITLOGCONFIGURATION, "");
        	LogConfigurationData lcd = LogConfigurationData.findByPK(entityManager, Integer.valueOf(caid));
        	if (lcd != null) {
        		lcd.saveLogConfiguration(logconfiguration);
        	} else { 
        		String msg = intres.getLocalizedMessage("log.createconf", new Integer(caid));            	
        		log.info(msg);
        		entityManager.persist(new LogConfigurationData(new Integer(caid), logconfiguration));
        	}
        } catch (Exception e) {
            log(admin, caid, LogConstants.MODULE_LOG, new Date(), null, null, LogConstants.EVENT_ERROR_EDITLOGCONFIGURATION, "");
            throw new EJBException(e);
        }
    }

    /**
     * Clear and reload log profile caches.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void flushConfigurationCache() {
    	logConfCache = new ObjectCache(EjbcaConfiguration.getCacheLogConfigurationTime());
    	if (log.isDebugEnabled()) {
    		log.debug("Flushed log configuration cache.");
    	}
    }

	/**
     * Methods for testing that a log-row is never rolled back if the rest of the transaction is.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public void testRollback(long rollbackTestTime) {
		Admin internalAdmin = new Admin(Admin.TYPE_INTERNALUSER);
		log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_CUSTOM, new Date(rollbackTestTime), null, null,
				LogConstants.EVENT_INFO_UNKNOWN, "Test of rollback resistance of log-system.", null);
		throw new EJBException("Test of rollback resistance of log-system.");
	}
}
