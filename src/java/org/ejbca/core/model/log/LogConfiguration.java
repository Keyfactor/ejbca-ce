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

package org.ejbca.core.model.log;

import java.io.Serializable;
import java.util.HashMap;


/**
 * Class containing the log configuration data. Tells which events should be logged and if internal
 * log database and/or external logging device should be used.
 *
 * @version $Id$
 */
public class LogConfiguration implements Serializable {
    
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = -6349974447455748715L;
    
    // Public constants
    // Constructors
    public LogConfiguration() {
        this.useexternaldevices = true;
        this.uselogdb = true;
        this.configurationdata = new HashMap();

        // Fill log configuration data with values from LogEntry constants. Default is true for all events.
        for (int i = 0; i < LogConstants.EVENTNAMES_INFO.length; i++) {
            configurationdata.put(new Integer(i), Boolean.TRUE);
        }

        for (int i = 0; i < LogConstants.EVENTNAMES_ERROR.length; i++) {
            configurationdata.put(new Integer(i + LogConstants.EVENT_ERROR_BOUNDRARY), Boolean.TRUE);
        }
    }
    /** Used for upgrading from EJBCA 3.1.x to 3.2.x.
     * TODO: remove this whole class method for EJBCA 3.3.
     */
    public LogConfiguration(boolean usedb, boolean useext, HashMap data) {
        this.configurationdata = data;
        this.uselogdb = usedb;
        this.useexternaldevices = useext;
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
        if (event >= LogConstants.EVENT_ERROR_BOUNDRARY) {
            return LogConstants.EVENTNAMES_ERROR[event];
        }
        return LogConstants.EVENTNAMES_INFO[event];
    }

    // Private fields
    private HashMap configurationdata;
    private boolean uselogdb;
    private boolean useexternaldevices;
}
