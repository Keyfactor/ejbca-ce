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

package org.ejbca.core.ejb.audit;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
//import java.security.MessageDigest;
//import java.security.NoSuchAlgorithmException;
//import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.log4j.Logger;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
//import org.cesecore.audit.AuditDevicesConfig;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.impl.AuditExporterXml;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.util.XmlSerializer;
//import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
//import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceRequest;
//import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceResponse;
import org.ejbca.core.model.util.EjbLocalHelper;

//import com.thoughtworks.xstream.io.path.Path;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;

/**
 * Export audit logs to XML file
 * 
 * @version $Id$
 */
public class XmlAuditExporter {

    private static final Logger log = Logger.getLogger(XmlAuditExporter.class);
    private static final String device = "IntegrityProtectedDevice";
    private static final String hashAlgorithm = "SHA-256";
    private static AuthenticationToken token;
    //private static List<? extends AuditLogEntry> results;
    //private static List<? extends AuditLogEntry> last_event_log;
    //private static Map<String, Object> additional_details;
    static SecurityEventsLoggerSessionLocal sessionLocal;

    static int minutes_xml;
    static String path_xml;
    static Timer timer_xml;
    //static String path_cms;
    //static String ca;
    //static Long first_log;
    //static Long last_log;

    public static String getDevice() {
        return device;
    }

    /*     private static byte[] exportToByteArray() throws IOException {
        // We could extend this without too much problems to allow the admin to choose between different formats.
        // By reading it from the config we could drop a custom exporter in the class-path and use it if configured
        final Class<? extends AuditExporter> exporterClass = AuditDevicesConfig.getExporter(getDevice());
        AuditExporter auditExporter = null;
        if (exporterClass != null) {
            if (log.isDebugEnabled()) {
                log.debug("Using AuditExporter class: " + exporterClass.getName());
            }
    
            try {
                auditExporter = exporterClass.newInstance();
            } catch (Exception e) {
                log.warn("AuditExporter for " + getDevice() + " is not configured correctly.", e);
            }
        }
    
        if (auditExporter == null) {
            if (log.isDebugEnabled()) {
                log.debug("AuditExporter not configured. Using default: " + AuditExporterXml.class.getSimpleName());
            }
            auditExporter = new AuditExporterXml(); // Use Java-friendly XML as default
        }
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            auditExporter.setOutputStream(baos);
            for (final AuditLogEntry auditLogEntry : results) {
                writeToExport(auditExporter, (AuditRecordData) auditLogEntry);
            }
            auditExporter.close();
            return baos.toByteArray();
        }
    } */

    // "Duplicate" of code from org.cesecore.audit.impl.integrityprotected.IntegrityProtectedAuditorSessionBean.writeToExport
    // (unusable from here.. :/)
    /** We want to export exactly like it was stored in the database, to comply with requirements on logging systems where no altering of the original log data is allowed. */
    private static void writeToExport(final AuditExporter auditExporter, final AuditRecordData auditRecordData) throws IOException {
        auditExporter.writeStartObject();
        auditExporter.writeField("pk", auditRecordData.getPk());
        auditExporter.writeField(AuditLogEntry.FIELD_NODEID, auditRecordData.getNodeId());
        auditExporter.writeField(AuditLogEntry.FIELD_SEQUENCENUMBER, auditRecordData.getSequenceNumber());
        auditExporter.writeField(AuditLogEntry.FIELD_TIMESTAMP, auditRecordData.getTimeStamp());
        auditExporter.writeField(AuditLogEntry.FIELD_EVENTTYPE, auditRecordData.getEventTypeValue().toString());
        auditExporter.writeField(AuditLogEntry.FIELD_EVENTSTATUS, auditRecordData.getEventStatusValue().toString());
        auditExporter.writeField(AuditLogEntry.FIELD_AUTHENTICATION_TOKEN, auditRecordData.getAuthToken());
        auditExporter.writeField(AuditLogEntry.FIELD_SERVICE, auditRecordData.getServiceTypeValue().toString());
        auditExporter.writeField(AuditLogEntry.FIELD_MODULE, auditRecordData.getModuleTypeValue().toString());
        auditExporter.writeField(AuditLogEntry.FIELD_CUSTOM_ID, auditRecordData.getCustomId());
        auditExporter.writeField(AuditLogEntry.FIELD_SEARCHABLE_DETAIL1, auditRecordData.getSearchDetail1());
        auditExporter.writeField(AuditLogEntry.FIELD_SEARCHABLE_DETAIL2, auditRecordData.getSearchDetail2());
        final Map<String, Object> additionalDetails = XmlSerializer.decode(auditRecordData.getAdditionalDetails());
        final String additionalDetailsEncoded = XmlSerializer.encodeWithoutBase64(additionalDetails);
        auditExporter.writeField(AuditLogEntry.FIELD_ADDITIONAL_DETAILS, additionalDetailsEncoded);
        auditExporter.writeField("rowProtection", auditRecordData.getRowProtection());
        auditExporter.writeField("rowVersion", auditRecordData.getRowVersion()); //added
        auditExporter.writeEndObject();
    }

    /**
    * Build and executing audit log queries that are safe from SQL injection.
    * 
    * @param token the requesting entity. Will also limit the results to authorized CAs. 
    * @param validColumns a Set of legal column names
    * @param device the name of the audit log device
    * @param conditions the list of conditions to transform into a query
    * @param sortColumn ORDER BY column
    * @param sortOrder true=ASC, false=DESC order
    * @param firstResult first entry from the result set. Index starts with 0.
    * @param maxResults number of results to return
    * @return the query result
    * @throws AuthorizationDeniedException if the administrator is not authorized to perform the requested query
    
    */
    /*     private static List<? extends AuditLogEntry> getResults() throws AuthorizationDeniedException {
    
        int firstResult = 0;
        int maxResults;
        String whereClause;
        final List<Object> parameters = new ArrayList<>();
    
        if (last_log == null) {
            maxResults = 0;
            whereClause = "a.eventType != ?0";
            parameters.add("");
        } else {
            maxResults = 0;
            whereClause = "a.sequenceNumber > ?0"; //a.eventType != ?0
            parameters.add(last_log);
        }
        System.out.println("WhereClause: " + whereClause);
        String orderClause = "a.timeStamp DESC";
        //Object condition = ""; //ACCESS_CONTROL
        //parameters.add(seq_number);
        //final List<Object> parameters = null;
    
        return new EjbLocalHelper().getEjbcaAuditorSession().selectAuditLog(token, device, firstResult, maxResults, whereClause, orderClause,
                parameters);
    }
     */
    /* 
    private static List<? extends AuditLogEntry> getLogSign() throws AuthorizationDeniedException {
        int firstResult = 0;
        int maxResults = 1;
        final List<Object> parameters = new ArrayList<>();
        String orderClause = "a.timeStamp DESC";
        String whereClause = "a.eventType = ?0";
        parameters.add("LOG_SIGN");
        return new EjbLocalHelper().getEjbcaAuditorSession().selectAuditLog(token, device, firstResult, maxResults, whereClause, orderClause,
                parameters);
    
    }
     */
    /*     private static byte[] exportCms() throws NoSuchAlgorithmException {
        CmsCAServiceResponse resp = null;
        int at = path_cms.indexOf('.');
        try {
            final CmsCAServiceRequest request = new CmsCAServiceRequest(exportToByteArray(), CmsCAServiceRequest.MODE_SIGN);
            final CAAdminSession caAdminSession = new EjbLocalHelper().getCaAdminSession();
            resp = (CmsCAServiceResponse) caAdminSession.extendedService(token, Integer.valueOf(ca), request);
            Files.write(Paths.get(path_cms.substring(0, at) + "_" + first_log + path_cms.substring(at)), resp.getCmsDocument());
        } catch (Exception e) {
            log.info("Administration tried to export audit log, but failed. " + e.getMessage());
        }
        // register the BouncyCastleProvider with the Security Manager
        Security.addProvider(new BouncyCastleProvider());
    
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hashedString = messageDigest.digest(resp.getCmsDocument());
    
        return hashedString;
    }
     */
    /* 
    private static void SecurelogWithAdditionalDetails(byte[] hash) throws AuditRecordStorageException, AuthorizationDeniedException {
        System.out.println("testing additional details");
        Map<String, Object> additionalDetails = new HashMap<String, Object>();
        EventTypes event = null;
        if (hash != null) {
            additionalDetails.put("hash", Hex.toHexString(hash));
            additionalDetails.put("Hash_Algo", "SHA-256");
            event = EventTypes.LOG_SIGN;
    
        } else {
            event = EventTypes.LOG_XML;
        }
        additionalDetails.put("first_seqn", first_log);
        additionalDetails.put("last_seqn", last_log);
        sessionLocal.log(event, EventStatus.SUCCESS, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE, token.toString(), null, null, null,
                additionalDetails);
        System.out.println("Log Worked");
    }
     */

    /*     private static void configLoader() {
        try {
            final URL url = ConfigurationHolder.class.getResource("/conf/cesecore.properties");
            if (url != null) {
                final PropertiesConfiguration pc = ConfigurationHolder.loadProperties(url);
                minutes = pc.getInt("securityeventsaudit.xmlexporter.timermin", 30);
                path_log = pc.getString("securityeventsaudit.xmlexporter.path_log", "/tmp/auditlogfile.log");
                path_cms = pc.getString("securityeventsaudit.xmlexporter.path_cms", "/tmp/auditlogfile.p7m");
                ca = pc.getString("securityeventsaudit.xmlexporter.ca", null);
                System.out.println("minutes: " + minutes);
                System.out.println("path_log: " + path_log);
                System.out.println("path_cms: " + path_cms);
                System.out.println("ca: " + ca);
                log.info("Finished config");
            }
        } catch (ConfigurationException e) {
            log.error("Error initializing configuration: ", e);
        }
    } */

    /**
     * Export the security audit log to the XML file - scheduled execution 
     */
    /*
    static class ScheduledXml extends TimerTask {
        public void run() {
            log.info("Exporting security audit log to the XML file - scheduled execution");
            try {
    
                last_sign_log = getLogSign();
    
                if (!last_sign_log.isEmpty()) {
                    additional_details = last_sign_log.get(0).getMapAdditionalDetails();
                    last_log = (Long) additional_details.get("last_seqn");
                }
    
                results = getResults();
    
                if (!results.isEmpty() && !last_sign_log.isEmpty()) {
    
                    for (final AuditLogEntry auditLogEntry : results) {
                        System.out.println("Audit log entry sequenceN: " + auditLogEntry.getSequenceNumber());
                        //System.out.println("AdditionalDetails : " + auditLogEntry.getMapAdditionalDetails());
                    }
    
                    last_log = results.get(0).getSequenceNumber();
                    first_log = results.get(results.size() - 1).getSequenceNumber();
    
                    System.out.println("Last Sign Log: " + additional_details);
                    System.out.println("First Log: " + first_log);
                    System.out.println("Last Log: " + last_log);
    
                    exportLogXml();
                    SecurelogWithAdditionalDetails(null);
    
                    byte[] hash = exportCms();
                    SecurelogWithAdditionalDetails(hash);
                }
            } catch (IOException e) {
                log.warn(e.getMessage());
            }
            //timer.cancel(); //Terminate the timer thread
            catch (AuthorizationDeniedException e) {
                log.warn(e.getMessage());
            } catch (NoSuchAlgorithmException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    } 
    */

    /*     
    public static void startTimer() throws AuditRecordStorageException, AuthorizationDeniedException {
        timer = new Timer();
        timer.schedule(new ScheduledXml(), 0, minutes * 60000);
    } 
    */

    /**
     * Initialize and configure the security audit logs environment
     * 
     * @param authenticationToken 
     * @param logSession
     * @throws AuditRecordStorageException
     * @throws AuthorizationDeniedException
     */
    public static void startCustomLogging(AuthenticationToken authenticationToken, SecurityEventsLoggerSessionLocal logSession)
            throws AuditRecordStorageException, AuthorizationDeniedException {
        setauth(authenticationToken);
        setLogSession(logSession);
        if (configExportXml()) { // if the extraction of the security audit events to the XML log file is enabled
            log.info("Extraction of the security audit events to the XML log file is enabled.");
            startExportXmlTimer();
        } else {
            log.info("Extraction of the security audit events to the XML log file is NOT enabled.");
        }
    }

    /**
     * Set AuthenticationToken token.
     * 
     * @param auth AuthenticationToken
     */
    public static void setauth(AuthenticationToken auth) {
        token = auth;
    }

    /**
     * Set SecurityEventsLoggerSessionLocal logsession
     * 
     * @param logsession SecurityEventsLoggerSessionLocal
     */
    public static void setLogSession(SecurityEventsLoggerSessionLocal logsession) {
        sessionLocal = logsession;
    }

    /**
     * Initialize the environment for exporting the events to an XML file. 
     * The following properties should be configured in the cesecore.properties file:
     * <ul>
     *   <li> securityeventsaudit.xmlexporter.enable - enables the extraction of the security audit events to the XML log file
     *   <li> securityeventsaudit.xmlexporter.path_log - path of the security audit log file
     *   <li> securityeventsaudit.xmlexporter.timermin - time frequency (in minutes) at which the security audit log is exported 
     * </ul> 
     * 
     * @return true, if the extraction of the security audit events to the XML log file is enabled 
     */
    private static boolean configExportXml() {
        boolean enable = false;
        try {
            final URL url = ConfigurationHolder.class.getResource("/conf/cesecore.properties");
            if (url != null) {
                final PropertiesConfiguration pc = ConfigurationHolder.loadProperties(url);
                enable = pc.getBoolean("securityeventsaudit.xmlexporter.enable", true);
                log.debug("The extraction of the security audit events to the XML log file is: " + enable);
                minutes_xml = pc.getInt("securityeventsaudit.xmlexporter.timermin", 10);
                log.debug("Configured time frequency (in minutes) at which the security audit log is extracted: " + minutes_xml);
                path_xml = pc.getString("securityeventsaudit.xmlexporter.path_log", "/tmp/");
                log.debug("Configured path of the security audit log file: " + path_xml);
            }
        } catch (ConfigurationException e) {
            log.error("Error initializing environment for exporting the events to an XML file: ", e);
        }
        return enable;
    }

    /**
     * Start the timer (time frequency (in minutes) at which the security audit log is exported to the XML file)
     * 
     * @throws AuditRecordStorageException
     * @throws AuthorizationDeniedException
     */
    public static void startExportXmlTimer() throws AuditRecordStorageException, AuthorizationDeniedException {
        timer_xml = new Timer();
        timer_xml.schedule(new ScheduledXml(), 0, minutes_xml * 60000);
        log.debug("Timer for extraction of the security audit events to the XML log file has started. The extraction will occur every " + minutes_xml
                + " minutes.");
    }

    /**
     * Export the security audit log to the XML file - scheduled execution 
     */
    static class ScheduledXml extends TimerTask {
        public void run() {
            List<? extends AuditLogEntry> last_event_log, results;
            Long last_log = (long) -1;
            Long first_log = (long) -1;

            log.info("Exporting security audit log to the XML file - scheduled execution");
            try {
                //get last successful LOG_XML event (meaning last time that the events were exported to the XML file) 
                last_event_log = getLastLog(EventTypes.LOG_XML, EventStatus.SUCCESS);

                if (!last_event_log.isEmpty()) {
                    last_log = Long.valueOf(last_event_log.get(0).getSearchDetail1());
                }

                results = getResults(last_log);

                if (!results.isEmpty()) { // if there are events not exported to the XML file

                    if (log.isDebugEnabled()) {
                        for (final AuditLogEntry auditLogEntry : results) {
                            log.debug("Audit log entry sequence Number to write to XML file: " + auditLogEntry.getSequenceNumber() + " - "
                                    + auditLogEntry.toString());
                        }
                    }

                    first_log = results.get(0).getSequenceNumber(); // first result has the highest sequence number
                    last_log = results.get(results.size() - 1).getSequenceNumber();

                    exportLog(Paths.get(path_xml + "auditlogfile_" + first_log + ".log"), results);
                    SecurelogWithAdditionalDetails(EventStatus.SUCCESS, EventTypes.LOG_XML, first_log.toString(), last_log.toString(), null, "");
                }
            } catch (IOException e) {
                log.error("Error (IOException) exporting security audit log to the XML file: ", e);
                try {
                    SecurelogWithAdditionalDetails(EventStatus.FAILURE, EventTypes.LOG_XML, first_log.toString(), last_log.toString(), null,
                            "Error (IOException) exporting security audit log to the XML file: " + e);
                } catch (AuditRecordStorageException | AuthorizationDeniedException e1) {
                    log.error(
                            "Error (AuditRecordStorageException | AuthorizationDeniedException) exporting security audit log to the XML file. Unable to store audit event in the Database: ",
                            e);
                }
            }
            //timer.cancel(); //Terminate the timer thread
            catch (AuditRecordStorageException | AuthorizationDeniedException e) {
                log.error(
                        "Error (AuditRecordStorageException | AuthorizationDeniedException) exporting security audit log to the XML file. Unable to store audit event in the Database: ",
                        e);
            }
        }
    }

    /**
     * Return last recorded auditlog of EventTypes event and of EventStatus status
     * 
     * @param event type of event
     * @param status status of event
     * @return list with last (newest) recorded auditlog of EventTypes event
     * @throws AuthorizationDeniedException
     */
    private static List<? extends AuditLogEntry> getLastLog(EventTypes event, EventStatus status) throws AuthorizationDeniedException {
        final List<Object> parameters = new ArrayList<>();

        parameters.add(event.toString());
        parameters.add(status.toString());
        return new EjbLocalHelper().getEjbcaAuditorSession().selectAuditLog(token, device, 0, 1, "a.eventType = ?0 AND a.eventStatus = ?1",
                "a.timeStamp DESC", parameters);
    }

    /**
     * Get all the security audit events from Database, with sequential number greater than last_log
     * 
     * @param last_log sequential number of the security audit event
     * @return list of security audit events with sequential number greater than last_log
     * @throws AuthorizationDeniedException
     */
    private static List<? extends AuditLogEntry> getResults(Long last_log) throws AuthorizationDeniedException {
        final List<Object> parameters = new ArrayList<>();

        parameters.add(last_log);

        return new EjbLocalHelper().getEjbcaAuditorSession().selectAuditLog(token, device, 0, 0, "a.sequenceNumber > ?0", "a.timeStamp DESC",
                parameters);
    }

    /**
     * Export security auditlog to file
     * 
     * @param path Path to the file
     * @param results list of events (security auditlogs)
     * @throws IOException
     */
    private static void exportLog(java.nio.file.Path path, List<? extends AuditLogEntry> results) throws IOException {
        Files.write(path, exportToByteArray(results));
        log.info("Security audit log exported to file " + path);
    }

    /**
     * Returns list of events as a byte array
     * 
     * @param results list of events
     * @return results as a byte array
     * @throws IOException
     */
    private static byte[] exportToByteArray(List<? extends AuditLogEntry> results) throws IOException {
        AuditExporter auditExporter = new AuditExporterXml();

        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            auditExporter.setOutputStream(baos);
            for (final AuditLogEntry auditLogEntry : results) {
                writeToExport(auditExporter, (AuditRecordData) auditLogEntry);
            }
            auditExporter.close();
            return baos.toByteArray();
        }
    }

    /**
     * Write security audit event to Database.
     * In the database table, searchDetail1 will contain the first log exported (highest sequencial number) and 
     * searchDetail2 will contain the last log exported )lowest sequential number).
     * If present, Hash, Hash_algo and Error_msg are stored in the additionalDetails table column.
     * 
     * @param status status of event
     * @param event type of event
     * @param searchDetail1 content to put in the searchDetail1 column (should be sequential number of first event - highest sequential number -, if it needs to be recorded)
     * @param searchDetail2 content to put in the searchDetail1 column (should be sequential number of last event - lowest sequential number -, if it needs to be recorded)
     * @param hash hash, if the event needs to record the hash
     * @param error_msg error message, if the event needs to record an error message
     * @throws AuditRecordStorageException
     * @throws AuthorizationDeniedException
     */
    private static void SecurelogWithAdditionalDetails(EventStatus status, EventTypes event, String searchDetail1, String searchDetail2, byte[] hash,
            String error_msg) throws AuditRecordStorageException, AuthorizationDeniedException {
        Map<String, Object> additionalDetails = new HashMap<String, Object>();
        String h = "";

        if (hash != null) {
            h = Hex.toHexString(hash);
            additionalDetails.put("Hash", h);
            additionalDetails.put("Hash_algo", hashAlgorithm);
        }
        if (status == EventStatus.FAILURE) {
            additionalDetails.put("Error_msg", error_msg);
        }
        sessionLocal.log(event, status, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE, token.toString(), null, searchDetail1, searchDetail2,
                additionalDetails);
        log.debug("Added security audit event to Database. Event type: " + event.toString() + "; Event status: " + status.toString()
                + "; searchDetail1: " + searchDetail1 + "; searchDetail2: " + searchDetail2 + "; Hash: " + h + "; error_msg: " + error_msg);
    }

}
