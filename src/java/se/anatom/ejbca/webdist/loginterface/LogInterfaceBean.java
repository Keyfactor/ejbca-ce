package se.anatom.ejbca.webdist.loginterface;

import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;

import javax.naming.*;
import javax.servlet.http.HttpServletRequest;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.log.*;
import se.anatom.ejbca.ra.authorization.AdminInformation;
import se.anatom.ejbca.util.query.*;
import se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean;


/**
 * A java bean handling the interface between EJBCA log module and JSP pages.
 *
 * @author Philip Vendil
 * @version $Id: LogInterfaceBean.java,v 1.9 2003-07-24 08:43:33 anatom Exp $
 */
public class LogInterfaceBean {
    // Public constants.
    public static final int MAXIMUM_QUERY_ROWCOUNT = ILogSessionRemote.MAXIMUM_QUERY_ROWCOUNT;

    /**
     * Creates new LogInterfaceBean
     */
    public LogInterfaceBean() {
    }

    // Public methods.

    /**
     * Method that initialized the bean.
     *
     * @param request is a reference to the http request.
     * @param ejbcawebbean DOCUMENT ME!
     */
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean)
        throws Exception {
        if (!initialized) {
            admin = new Admin(((X509Certificate[]) request.getAttribute(
                        "javax.servlet.request.X509Certificate"))[0]);

            InitialContext jndicontext = new InitialContext();
            ILogSessionHome logsessionhome = (ILogSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "LogSession"), ILogSessionHome.class);
            logsession = logsessionhome.create();

            ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "CertificateStoreSession"), ICertificateStoreSessionHome.class);
            certificatesession = certificatesessionhome.create();

            logauthorization = new LogAuthorization(ejbcawebbean);

            initializeEventNameTables(ejbcawebbean);

            dnproxy = new SubjectDNProxy(admin, certificatesession);
            logentriesview = new LogEntriesView(dnproxy, localinfoeventnamesunsorted,
                    localerroreventnamesunsorted, localmodulenamesunsorted);
            initialized = true;
        }
    }

    /**
     * Method that searches the log database for all events occurred related to the given query.
     *
     * @param query the query to use.
     * @param index point's where in result to begin returning data.
     * @param size the number of elements to return.
     *
     * @return DOCUMENT ME!
     */
    public LogEntryView[] filterByQuery(Query query, int index, int size)
        throws Exception {
        Collection logentries = (Collection) logsession.query(query,
                logauthorization.getViewLogRights());
        logentriesview.setEntries(logentries);

        return logentriesview.getEntries(index, size);
    }

    /**
     * Method that searches the log database for all events occurred related to the given username.
     * Used in the view user history page.
     *
     * @param username the username to search for
     *
     * @return DOCUMENT ME!
     */
    public LogEntriesView filterByUsername(String username)
        throws Exception {
        LogEntriesView returnval = new LogEntriesView(dnproxy, localinfoeventnamesunsorted,
                localerroreventnamesunsorted, localmodulenamesunsorted);

        Query query = new Query(Query.TYPE_LOGQUERY);
        query.add(LogMatch.MATCH_WITH_USERNAME, BasicMatch.MATCH_TYPE_EQUALS, username);

        Collection logentries = (Collection) logsession.query(query,
                logauthorization.getViewLogRights());
        returnval.setEntries(logentries);

        return returnval;
    }

    /**
     * Method that searches the log database for all events occurred within the last given minutes.
     * Used in the view user history page.
     *
     * @param time the time in minutes to look for.
     * @param index point's where in result to begin returning data.
     * @param size the number of elements to return.
     *
     * @return DOCUMENT ME!
     */
    public LogEntryView[] filterByTime(int time, int index, int size)
        throws Exception {
        Query query = new Query(Query.TYPE_LOGQUERY);
        Date starttime = new Date((new Date()).getTime() - (time * 60000));

        query.add(starttime, new Date());

        Collection logentries = (Collection) logsession.query(query,
                logauthorization.getViewLogRights());
        logentriesview.setEntries(logentries);

        return logentriesview.getEntries(index, size);
    }

    /* Method that returns the size of a query search */
    public int getResultSize() {
        return logentriesview.size();
    }

    /* Method to resort filtered user data. */
    public void sortUserData(int sortby, int sortorder) {
        logentriesview.sortBy(sortby, sortorder);
    }

    /* Method to return the logentries between index and size, if logentries is smaller than size, a smaller array is returned. */
    public LogEntryView[] getEntries(int index, int size) {
        return logentriesview.getEntries(index, size);
    }

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     * @param size DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean nextButton(int index, int size) {
        return (index + size) < logentriesview.size();
    }

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     * @param size DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean previousButton(int index, int size) {
        return index > 0;
    }

    /**
     * Loads the log configuration from the database.
     *
     * @return the logconfiguration
     */
    public LogConfiguration loadLogConfiguration() throws RemoteException {
        return logsession.loadLogConfiguration();
    }

    /**
     * Saves the log configuration to the database.
     *
     * @param logconfiguration the logconfiguration to save.
     */
    public void saveLogConfiguration(LogConfiguration logconfiguration)
        throws RemoteException {
        logsession.saveLogConfiguration(admin, logconfiguration);
    }

    /**
     * Help methods that sets up id mappings between   event ids and  event names in local
     * languange.
     *
     * @return a hasmap with error info eventname to id mappings.
     */
    public HashMap getEventNameToIdMap() {
        return localeventnamestoid;
    }

    /**
     * Help methods that sets up id mappings between  module ids and module names in local
     * languange.
     *
     * @return a hasmap with error info eventname to id mappings.
     */
    public HashMap getModuleNameToIdMap() {
        return localmodulenamestoid;
    }

    /**
     * Help methods that translates info event names to the local languange.
     *
     * @return an array with local info eventnames.
     */
    public String[] getLocalInfoEventNames() {
        return localinfoeventnames;
    }

    /**
     * Help methods that translates error event names to the local languange.
     *
     * @return an array with local info eventnames.
     */
    public String[] getLocalErronEventNames() {
        return localerroreventnames;
    }

    /**
     * Help methods that returns an array with all translated event names.
     *
     * @return an array of all translated eventnames.
     */
    public String[] getAllLocalEventNames() {
        return alllocaleventnames;
    }

    /**
     * Help methods that returns an array with all translated module names.
     *
     * @return an array of all translated eventnames.
     */
    public String[] getLocalModuleNames() {
        return localmodulenames;
    }

    // Private methods.
    private void initializeEventNameTables(EjbcaWebBean ejbcawebbean) {
        int alleventsize = LogEntry.EVENTNAMES_INFO.length + LogEntry.EVENTNAMES_ERROR.length;
        alllocaleventnames = new String[alleventsize];
        localinfoeventnames = new String[LogEntry.EVENTNAMES_INFO.length];
        localinfoeventnamesunsorted = new String[LogEntry.EVENTNAMES_INFO.length];
        localeventnamestoid = new HashMap();

        for (int i = 0; i < localinfoeventnames.length; i++) {
            localinfoeventnames[i] = ejbcawebbean.getText(LogEntry.EVENTNAMES_INFO[i]);
            localinfoeventnamesunsorted[i] = ejbcawebbean.getText(LogEntry.EVENTNAMES_INFO[i]);
            alllocaleventnames[i] = localinfoeventnames[i];
            localeventnamestoid.put(localinfoeventnames[i], new Integer(i));
        }

        Arrays.sort(localinfoeventnames);

        localerroreventnamesunsorted = new String[LogEntry.EVENTNAMES_ERROR.length];
        localerroreventnames = new String[LogEntry.EVENTNAMES_ERROR.length];

        for (int i = 0; i < localerroreventnames.length; i++) {
            localerroreventnames[i] = ejbcawebbean.getText(LogEntry.EVENTNAMES_ERROR[i]);
            localerroreventnamesunsorted[i] = localerroreventnames[i];
            alllocaleventnames[LogEntry.EVENTNAMES_ERROR.length + i] = localerroreventnames[i];
            localeventnamestoid.put(localerroreventnames[i],
                new Integer(i + LogEntry.EVENT_ERROR_BOUNDRARY));
        }

        Arrays.sort(localerroreventnames);
        Arrays.sort(alllocaleventnames);

        localmodulenames = new String[LogEntry.MODULETEXTS.length];
        localmodulenamesunsorted = new String[LogEntry.MODULETEXTS.length];
        localmodulenamestoid = new HashMap(9);

        for (int i = 0; i < localmodulenames.length; i++) {
            localmodulenames[i] = ejbcawebbean.getText(LogEntry.MODULETEXTS[i]);
            localmodulenamesunsorted[i] = localmodulenames[i];
            localmodulenamestoid.put(localmodulenames[i], new Integer(i));
        }

        Arrays.sort(localmodulenames);
    }

    // Private fields.
    private ICertificateStoreSessionRemote certificatesession;
    private ILogSessionRemote logsession;
    private LogEntriesView logentriesview;
    private Admin admin;
    private SubjectDNProxy dnproxy;
    private boolean initialized = false;
    private LogAuthorization logauthorization;
    private HashMap localeventnamestoid;
    private HashMap localmodulenamestoid;
    private String[] localinfoeventnames;
    private String[] localerroreventnames;
    private String[] localinfoeventnamesunsorted;
    private String[] localerroreventnamesunsorted;
    private String[] alllocaleventnames;
    private String[] localmodulenames;
    private String[] localmodulenamesunsorted;
}
