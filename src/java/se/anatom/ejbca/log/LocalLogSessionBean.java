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
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Properties;
import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.util.CertTools;
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
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.env-entry
 *   name="Datasource"
 *   type="java.lang.String"
 *   value="java:/DefaultDS"
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
 */
public class LocalLogSessionBean extends BaseSessionBean {

    private static final Logger log = Logger.getLogger(LocalLogSessionBean.class);

    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    /** The home interface of  LogEntryData entity bean */
    private LogEntryDataLocalHome logentryhome = null;

    /** The home interface of  LogConfigurationData entity bean */
    private LogConfigurationDataLocalHome logconfigurationhome = null;

    /** The remote interface of the LogConfigurationData entity bean */
    private LogConfigurationDataLocal logconfigurationdata = null;


    /** Collection of available log devices, i.e Log4j etc */
    private ArrayList logdevices = null;

    /** Columns in the database used in select */
    private final String LOGENTRYDATA_COL = "adminType, adminData, caid, module, time, username, certificateSNR, event, comment";

    /**
     * Default create for SessionBean without any creation Arguments.
     */
    public void ejbCreate() {
        try {
            debug(">ejbCreate()");
            dataSource = (String) lookup("java:comp/env/DataSource", java.lang.String.class);
            debug("DataSource=" + dataSource);

            logentryhome = (LogEntryDataLocalHome) lookup("java:comp/env/ejb/LogEntryDataLocal", LogEntryDataLocalHome.class);
            logconfigurationhome = (LogConfigurationDataLocalHome) lookup("java:comp/env/ejb/LogConfigurationDataLocal", LogConfigurationDataLocalHome.class);


            // Setup Connection to signing devices.
            logdevices = new ArrayList();

            // Get configuration of log device classes from ejb-jar.xml
            String factoryclassesstring = (String) lookup("java:comp/env/logDeviceFactories", java.lang.String.class);
            String propertyfilesstring = (String) lookup("java:comp/env/logDevicePropertyFiles", java.lang.String.class);

            String[] factoryclasses = factoryclassesstring.split(";");
            String[] propertyfiles = propertyfilesstring.split(";");

            Properties[] properties = new Properties[propertyfiles.length];
            for (int i = 0; i < propertyfiles.length; i++) {
                properties[i] = new Properties();
                if (!(propertyfiles[i] == null || propertyfiles[i].trim().equals("")))
                    properties[i].load(this.getClass().getResourceAsStream("/logdeviceproperties/" + propertyfiles[i].trim()));
            }

            for (int i = 0; i < factoryclasses.length; i++) {
                Class implClass = Class.forName(factoryclasses[i].trim());
                Object fact = implClass.newInstance();
                Class[] paramTypes = new Class[1];
                paramTypes[0] = properties[0].getClass();
                Method method = implClass.getMethod("makeInstance", paramTypes);
                Object[] params = new Object[1];
                if (i < properties.length)
                    params[0] = properties[i];
                else
                    params[0] = new Properties();
                logdevices.add((ILogDevice) method.invoke(fact, params));
            }
            debug("<ejbCreate()");
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }


    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource) getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection

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
        try {
            LogConfiguration logconfiguration = loadLogConfiguration(caid);


            // Get logging configuration
            if (logconfiguration.logEvent(event)) {
                if (logconfiguration.useLogDB()) {
                    try {
                        // Log to the local database.
                        if (certificate != null) {
                            String uniquecertificatesnr = certificate.getSerialNumber().toString(16) + "," + CertTools.getIssuerDN(certificate);
                            logentryhome.create(this.getAndIncrementRowCount(), admin.getAdminType(), admin.getAdminData(), caid, module, time, username,
                                    uniquecertificatesnr, event, comment);
                        } else
                            logentryhome.create(this.getAndIncrementRowCount(), admin.getAdminType(), admin.getAdminData(), caid, module, time, username,
                                    null, event, comment);
                    } catch (javax.ejb.DuplicateKeyException dke) {
                        this.getAndIncrementRowCount();
                    }
                }
                if (logconfiguration.useExternalLogDevices()) {
                    // Log to external devices. I.e Log4j etc
                    Iterator i = logdevices.iterator();
                    while (i.hasNext()) {
                        ((ILogDevice) i.next()).log(admin, caid, module, time, username, certificate, event, comment);
                    }
                }
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }

    } // log

    /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of
     * given certificate.
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
        try {
            LogConfiguration logconfiguration = loadLogConfiguration(caid);


            // Get logging configuration
            if (logconfiguration.logEvent(event)) {
                if (logconfiguration.useLogDB()) {
                    try {
                        // Log to the local database.
                        if (certificate != null) {
                            String uniquecertificatesnr = certificate.getSerialNumber().toString(16) + "," + certificate.getIssuerDN().toString();
                            logentryhome.create(this.getAndIncrementRowCount(), admin.getAdminType(), admin.getAdminData(), caid, module, time, username,
                                    uniquecertificatesnr, event, comment);
                        } else
                            logentryhome.create(this.getAndIncrementRowCount(), admin.getAdminType(), admin.getAdminData(), caid, module, time, username,
                                    null, event, comment);
                    } catch (javax.ejb.DuplicateKeyException dke) {
                        this.getAndIncrementRowCount();
                    }
                }
                if (logconfiguration.useExternalLogDevices()) {
                    // Log to external devices. I.e Log4j etc
                    Iterator i = logdevices.iterator();
                    while (i.hasNext()) {
                        ((ILogDevice) i.next()).log(admin, caid, module, time, username, certificate, event, comment, exception);
                    }
                }
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }

    /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of
     * given certificate.
     *
     * @ejb.interface-method view-type="both"
     */
    public void log(Admin admin, X509Certificate caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception) {
        log(admin, CertTools.getIssuerDN(caid).hashCode(), module, time, username, certificate, event, comment, exception);
    } // log

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
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList returnval = new ArrayList();

        if (capriviledges == null || capriviledges.equals(""))
            throw new IllegalQueryException();


        // Check if query is legal.
        if (!query.isLegalQuery())
            throw new IllegalQueryException();
        try {
            // Construct SQL query.
            con = getConnection();
            if (viewlogprivileges.equals("")) {
                ps = con.prepareStatement("select " + LOGENTRYDATA_COL + " from LogEntryData where ( " + query.getQueryString() +
                        ") and (" + capriviledges + ")");
            } else {
                ps = con.prepareStatement("select " + LOGENTRYDATA_COL + " from LogEntryData where (" + query.getQueryString() + ") and ("
                        + viewlogprivileges + ") and (" + capriviledges + ")");

            }
            //ps.setFetchDirection(ResultSet.FETCH_REVERSE);
            ps.setFetchSize(LogConstants.MAXIMUM_QUERY_ROWCOUNT + 1);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            while (rs.next() && returnval.size() <= LogConstants.MAXIMUM_QUERY_ROWCOUNT) {
                LogEntry data = new LogEntry(rs.getInt(1), rs.getString(2), rs.getInt(3), rs.getInt(4), new java.util.Date(rs.getLong(5)), rs.getString(6), rs.getString(7)
                        , rs.getInt(8), rs.getString(9));
                returnval.add(data);
            }
            debug("<query()");
            return returnval;

        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            try {
                if (rs != null) rs.close();
                if (ps != null) ps.close();
                if (con != null) con.close();
            } catch (SQLException se) {
                error("Fel vid upprensning: ", se);
            }
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
                log(admin, caid, LogEntry.MODULE_LOG, new java.util.Date(), null, null, LogEntry.EVENT_INFO_EDITLOGCONFIGURATION, "");
            } catch (FinderException e) {
                logconfigurationhome.create(new Integer(caid), logconfiguration);
                log(admin, caid, LogEntry.MODULE_LOG, new java.util.Date(), null, null, LogEntry.EVENT_INFO_EDITLOGCONFIGURATION, "");
            }
        } catch (Exception e) {
            log(admin, caid, LogEntry.MODULE_LOG, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_EDITLOGCONFIGURATION, "");
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
