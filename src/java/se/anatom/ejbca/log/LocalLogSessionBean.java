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

package se.anatom.ejbca.log;

import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Properties;

import javax.ejb.CreateException;
import javax.ejb.DuplicateKeyException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.JNDINames;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.JDBCUtil;
import se.anatom.ejbca.util.query.IllegalQueryException;
import se.anatom.ejbca.util.query.Query;


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
 * @ejb.env-entry
 * name="DataSource"
 * type="java.lang.String"
 * value="java:/${datasource.jndi-name}"
 *
 * @ejb.env-entry
 *   description="String representing the log device factories to be used. The different device classes should be separated with semicolons (;)."
 *   name="logDeviceFactories"
 *   type="java.lang.String"
 *   value="se.anatom.ejbca.log.Log4jLogDeviceFactory"
 *
 * @ejb.env-entry
 *   description="String representing the property file corresponding to each log device.
 The property files should be placed in the '/logdeviceproperties' subdirectory.
 The filenames should be separated with semicolons (;)"
 *   name="logDevicePropertyFiles"
 *   type="java.lang.String"
 *   value="Log4j.properties"
 *
 * @ejb.ejb-external-ref
 *   description="The Log Entry Data entity bean"
 *   view-type="local"
 *   ejb-name="LogEntryDataLocal"
 *   type="Entity"
 *   home="se.anatom.ejbca.log.LogEntryDataLocalHome"
 *   business="se.anatom.ejbca.log.LogEntryDataLocal"
 *   link="LogEntryData"
 *
 * @ejb.ejb-external-ref
 *   description="The Log Configuration Data Entity bean"
 *   view-type="local"
 *   ejb-name="LogConfigurationDataLocal"
 *   type="Entity"
 *   home="se.anatom.ejbca.log.LogConfigurationDataLocalHome"
 *   business="se.anatom.ejbca.log.LogConfigurationDataLocal"
 *   link="LogConfigurationData"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome,LogConstants"
 *   local-class="se.anatom.ejbca.log.ILogSessionLocalHome"
 *   remote-class="se.anatom.ejbca.log.ILogSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject,LogConstants"
 *   local-class="se.anatom.ejbca.log.ILogSessionLocal"
 *   remote-class="se.anatom.ejbca.log.ILogSessionRemote"
 *
 * @jonas.bean
 *   ejb-name="LogSession"
 *
 * @version $Id: LocalLogSessionBean.java,v 1.30 2005-12-27 14:18:55 anatom Exp $
 */
public class LocalLogSessionBean extends BaseSessionBean {

    /** The home interface of  LogEntryData entity bean */
    private LogEntryDataLocalHome logentryhome;

    /** The home interface of  LogConfigurationData entity bean */
    private LogConfigurationDataLocalHome logconfigurationhome;

    /** The remote interface of the LogConfigurationData entity bean */
    private LogConfigurationDataLocal logconfigurationdata;

    private static final String LOGDEVICE_FACTORIES = "java:comp/env/logDeviceFactories";
    private static final String LOGDEVICE_PROPERTIES = "java:comp/env/logDevicePropertyFiles";

    /** Collection of available log devices, i.e Log4j etc */
    private ArrayList logdevices;

    /** Columns in the database used in select */
    private final String LOGENTRYDATA_TABLE = "LogEntryData";
    private final String LOGENTRYDATA_COL = "adminType, adminData, caid, module, time, username, certificateSNR, event";
    // Different column names is an unforturnalte workaround because of Orcale, you cannot have a column named 'comment' in Oracle.
    // The workaround 'comment_' was spread in the wild in 2005, so we have to use it so far.
    private final String LOGENTRYDATA_COL_COMMENT_OLD = "comment";
    private final String LOGENTRYDATA_COL_COMMENT_ORA = "comment_";

    /**
     * Default create for SessionBean without any creation Arguments.
     */
    public void ejbCreate() {
        try {
            logentryhome = (LogEntryDataLocalHome) getLocator().getLocalHome(LogEntryDataLocalHome.COMP_NAME);
            logconfigurationhome = (LogConfigurationDataLocalHome) getLocator().getLocalHome(LogConfigurationDataLocalHome.COMP_NAME);

            // Setup Connection to signing devices.
            logdevices = new ArrayList();

            // Get configuration of log device classes from ejb-jar.xml
            String factoryclassesstring = getLocator().getString(LOGDEVICE_FACTORIES);
            String propertyfilesstring = getLocator().getString(LOGDEVICE_PROPERTIES);

            String[] propertyfiles = propertyfilesstring.split(";");
            Properties[] properties = new Properties[propertyfiles.length];
            for (int i = 0; i < propertyfiles.length; i++) {
                properties[i] = new Properties();
                if (!(propertyfiles[i] == null || propertyfiles[i].trim().equals("")))
                    properties[i].load(this.getClass().getResourceAsStream("/logdeviceproperties/" + propertyfiles[i].trim()));
            }

            String[] factoryclasses = factoryclassesstring.split(";");
            for (int i = 0; i < factoryclasses.length; i++) {
                Class implClass = Class.forName(factoryclasses[i].trim());
                Object fact = implClass.newInstance();
                Class[] paramTypes = new Class[]{properties[0].getClass()};
                Method method = implClass.getMethod("makeInstance", paramTypes);
                Object[] params = new Object[1];
                if (i < properties.length)
                    params[0] = properties[i];
                else
                    params[0] = new Properties();
                logdevices.add(method.invoke(fact, params));
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }

    /**
     * Session beans main function. Takes care of the logging functionality.
     *
     * @param admin the administrator performing the event.
     * @param time the time the event occured.
     * @param username the name of the user involved or null if no user is involved.
     * @param certificate the certificate involved in the event or null if no certificate is involved.
     * @param event id of the event, should be one of the se.anatom.ejbca.log.LogEntry.EVENT_ constants.
     * @param comment comment of the event.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="RequiresNew"
     */
    public void log(Admin admin, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment) {
        doLog(admin, caid, module, time, username, certificate, event, comment, null);
    } // log

    /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of given certificate.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="RequiresNew"
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
     * @ejb.transaction type="RequiresNew"
     *
     */
    public void log(Admin admin, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception) {
        doLog(admin, caid, module, time, username, certificate, event, comment, exception);
    }

    /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of given certificate.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="RequiresNew"
     */
    public void log(Admin admin, X509Certificate caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception) {
        log(admin, CertTools.getIssuerDN(caid).hashCode(), module, time, username, certificate, event, comment, exception);
    } // log


    /**
     * Internal implementation for loggin
     */
    private void doLog(Admin admin, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception ex) {
        final LogConfiguration config = loadLogConfiguration(caid);
        if (config.logEvent(event)) {
            try {
                if (config.useLogDB()) {
                    logDB(admin, caid, module, time, username, certificate, event, comment);
                }
            } finally {
                // make sure to log here if the db fails
                if (config.useExternalLogDevices()) {
                    logExternal(admin, caid, module, time, username, certificate, event, comment, ex);
                }
            }
        }
    }

    /**
     * Make use of the external loggers
     */
    private void logExternal(Admin admin, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception ex) {
        Iterator i = logdevices.iterator();
        while (i.hasNext()) {
            ILogDevice dev = (ILogDevice) i.next();
            dev.log(admin, caid, module, time, username, certificate, event, comment, ex);
        }
    }

    /**
     * Log everything in the database using the log entity bean
     */
    private void logDB(Admin admin, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment)
            throws EJBException {
        try {
            String uid = certificate == null ? null : certificate.getSerialNumber().toString(16) + "," + certificate.getIssuerDN().toString();
            Integer id = getAndIncrementRowCount();
            logentryhome.create(id, admin.getAdminType(), admin.getAdminData(), caid, module, time, username, uid, event, comment);
        } catch (DuplicateKeyException e) {
            // FIXME we are losing a db audit entry in this case, what do we do ?
            getAndIncrementRowCount();
        } catch (CreateException e) {
            throw new EJBException(e);
        }
    }


    /**
     * Method to execute a customized query on the log db data. The parameter query should be a legal Query object.
     *
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @param viewlogprivileges is a sql query string returned by a LogAuthorization object.
     * @return a collection of LogEntry. Maximum size of Collection is defined i ILogSessionRemote.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @see se.anatom.ejbca.util.query.Query
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     *
     */
    public Collection query(Query query, String viewlogprivileges, String capriviledges) throws IllegalQueryException {
        debug(">query()");
        if (capriviledges == null || capriviledges.length() == 0 || !query.isLegalQuery()) {
            throw new IllegalQueryException();
        }

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            // Different column names is an unforturnalte workaround because of Orcale, you cannot have a column named 'comment' in Oracle.
            // The workaround 'comment_' was spread in the wild in 2005, so we have to use it so far.
            String commentCol = LOGENTRYDATA_COL_COMMENT_OLD;
            if (!JDBCUtil.columnExists(con, LOGENTRYDATA_TABLE, LOGENTRYDATA_COL_COMMENT_OLD)) {
                log.debug("Using oracle column name 'comment_' in LogEntryData.");
                commentCol = LOGENTRYDATA_COL_COMMENT_ORA;
            }
            String sql = "select "+LOGENTRYDATA_COL+", "+commentCol+" from "+LOGENTRYDATA_TABLE+" where ( "
                    + query.getQueryString() + ") and (" + capriviledges + ")";
            if (StringUtils.isNotEmpty(viewlogprivileges)) {
                sql += " and (" + viewlogprivileges + ")";
            }
            ps = con.prepareStatement(sql);
            //ps.setFetchDirection(ResultSet.FETCH_REVERSE);
            ps.setFetchSize(LogConstants.MAXIMUM_QUERY_ROWCOUNT + 1);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            ArrayList returnval = new ArrayList();
            while (rs.next() && returnval.size() <= LogConstants.MAXIMUM_QUERY_ROWCOUNT) {
                LogEntry data = new LogEntry(rs.getInt(1), rs.getString(2), rs.getInt(3), rs.getInt(4), new Date(rs.getLong(5)), rs.getString(6), rs.getString(7)
                        , rs.getInt(8), rs.getString(9));
                returnval.add(data);
            }
            return returnval;

        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
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
            try {
                logconfiguration = new LogConfiguration();
                logconfigdata = logconfigurationhome.create(new Integer(caid), logconfiguration);
            } catch (CreateException f) {
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
                log(admin, caid, LogEntry.MODULE_LOG, new Date(), null, null, LogEntry.EVENT_INFO_EDITLOGCONFIGURATION, "");
            } catch (FinderException e) {
                logconfigurationhome.create(new Integer(caid), logconfiguration);
                log(admin, caid, LogEntry.MODULE_LOG, new Date(), null, null, LogEntry.EVENT_INFO_EDITLOGCONFIGURATION, "");
            }
        } catch (Exception e) {
            log(admin, caid, LogEntry.MODULE_LOG, new Date(), null, null, LogEntry.EVENT_ERROR_EDITLOGCONFIGURATION, "");
            throw new EJBException(e);
        }
    } // saveLogConfiguration


    private Integer getAndIncrementRowCount() {
        if (this.logconfigurationdata == null) {
            try {
                logconfigurationdata = logconfigurationhome.findByPrimaryKey(new Integer(0));
            } catch (FinderException e) {
                try {
                    LogConfiguration logconfiguration = new LogConfiguration();
                    this.logconfigurationdata = logconfigurationhome.create(new Integer(0), logconfiguration);
                } catch (CreateException f) {
                    throw new EJBException(f);
                }
            }
        }

        return this.logconfigurationdata.getAndIncrementRowCount();
    }

} // LocalLogSessionBean
