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

import java.io.Serializable;
import java.util.HashMap;

import org.ejbca.core.model.log.LogEntry;


/**
 * TODO: remove this whole class method for EJBCA 3.3.
 * 
 * Class containing the log configuration data. Tells which events should be logged and if internal
 * log database and/or external logging device should be used.
 *
 * @version $Id: LogConfiguration.java,v 1.12 2006-01-26 14:18:20 anatom Exp $
 */
public class LogConfiguration implements Serializable {
    private static final long serialVersionUID = -6349974447455748715L;

    // Public constants
    // Constructors
    public LogConfiguration() {
        this.useexternaldevices = true;
        this.uselogdb = true;
        this.configurationdata = new HashMap();

        // Fill log configuration data with values from LogEntry constants. Default is true for all events.
        for (int i = 0; i < LogEntry.EVENTNAMES_INFO.length; i++) {
            configurationdata.put(new Integer(i), Boolean.TRUE);
        }

        for (int i = 0; i < LogEntry.EVENTNAMES_ERROR.length; i++) {
            configurationdata.put(new Integer(i + LogEntry.EVENT_ERROR_BOUNDRARY), Boolean.TRUE);
        }
    }

    // Public Methods
    public boolean logEvent(int event) {
        Boolean log = (Boolean) configurationdata.get(new Integer(event));

        if (log == null) {
            return true; // Default is log everything.
        }
        return log.booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param event DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Boolean getLogEvent(int event) {
        return (Boolean) configurationdata.get(new Integer(event));
    }

    /**
     * DOCUMENT ME!
     *
     * @param event DOCUMENT ME!
     * @param log DOCUMENT ME!
     */
    public void setLogEvent(int event, boolean log) {
        configurationdata.put(new Integer(event), Boolean.valueOf(log));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean useLogDB() {
        return uselogdb;
    }

    /**
     * DOCUMENT ME!
     *
     * @param use DOCUMENT ME!
     */
    public void setUseLogDB(boolean use) {
        this.uselogdb = use;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean useExternalLogDevices() {
        return this.useexternaldevices;
    }

    /**
     * DOCUMENT ME!
     *
     * @param use DOCUMENT ME!
     */
    public void setUseExternalLogDevices(boolean use) {
        this.useexternaldevices = use;
    }

    // Private functions
    public String getStringRepresentationOfEventId(int event) {
        if (event >= LogEntry.EVENT_ERROR_BOUNDRARY) {
            return LogEntry.EVENTNAMES_ERROR[event];
        }
        return LogEntry.EVENTNAMES_INFO[event];
    }
    /** Returns the complete map. Used for upgrading from EJBCA 3.1.x to 3.2.x.
     * TODO: remove this whole class method for EJBCA 3.3.
     * 
     * @return HashMap revealing internal implementation
     */
    public HashMap getConfigurationData() {
        return this.configurationdata;
    }

    // Private fields
    private HashMap configurationdata;
    private boolean uselogdb;
    private boolean useexternaldevices;
}
