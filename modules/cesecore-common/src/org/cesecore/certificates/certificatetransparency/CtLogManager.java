/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.cesecore.certificates.certificatetransparency;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

import org.apache.commons.lang.StringUtils;

/**
 * This class is responsible for managing a list of CT logs. The CT logs backed by
 * this class can be grouped or reordered and there is functionality for adding
 * new CT logs or removing existing ones. This class does not load or store changes
 * in a persistent storage, and relies on its creator to load the CT logs from e.g.
 * a database or a file.
 * @version $Id$
 */
public class CtLogManager {
    private final List<CTLogInfo> ctLogs;

    /**
     * Create a new CT log manager responsible for a list of logs specified.
     * @param ctLogs the logs managed by this CT log manager
     */
    public CtLogManager(final List<CTLogInfo> ctLogs) {
        this.ctLogs = ctLogs;
    }

    /**
     * Group the CT logs managed by this CT log manager by label. Returns a map
     * which maps a label to a list of all CT logs which has this label.
     * @return a mapping between labels and CT logs with this label
     */
    public LinkedHashMap<String, List<CTLogInfo>> getCtLogGroups() {
        final LinkedHashMap<String, List<CTLogInfo>> logLogMap = new LinkedHashMap<>();
        for (final CTLogInfo ctLog : ctLogs) {
            if (!logLogMap.containsKey(ctLog.getLabel())) {
                logLogMap.put(ctLog.getLabel(), new ArrayList<CTLogInfo>());
            }
            logLogMap.get(ctLog.getLabel()).add(ctLog);
        }
        return logLogMap;
    }

    /**
     * Returns all unique labels for the CT logs managed by this CT log manager.
     * @return a list of all unique labels
     */
    public List<String> getLabels() {
        return new ArrayList<String>(getCtLogGroups().keySet());
    }

    /**
     * Returns a list of all logs managed by this CT log manager. This list can be
     * persisted to a database and used to initialise an identical log manager.
     * @return a list of all CT logs
     */
    public List<CTLogInfo> getAllCtLogs() {
        return ctLogs;
    }

    /**
     * Get a list of CT logs labelled as specified. If no logs have the label specified,
     * an empty list will be returned.
     * @param label the label of the CT logs to retrieve
     * @return a list of CT logs matching the given label, never null
     */
    public List<CTLogInfo> getCtLogsByLabel(final String label) {
        final List<CTLogInfo> ctLogGroup = getCtLogGroups().get(label);
        if (ctLogGroup == null) {
            return new ArrayList<CTLogInfo>();
        }
        return ctLogGroup;
    }

    /**
     * Moves the specified CT log up one step. This method does nothing if the CT log is already
     * on top or if the CT log group to which the CT log belongs only contains one log.
     * @throws IllegalArgumentException if the CT log given as argument is not managed by this CT log manager
     */
    public void moveUp(final CTLogInfo ctLog) {
        final List<CTLogInfo> ctLogGroup = getCtLogsByLabel(ctLog.getLabel());
        if (!ctLogGroup.contains(ctLog)) {
            throw new IllegalArgumentException("The CT log " + ctLog.toString() + " is not managed by this CT log manager.");
        }
        if (ctLogGroup.size() == 1 || isOnTop(ctLog)) {
            return;
        }
        final CTLogInfo previousCtLog = ctLogGroup.get(ctLogGroup.indexOf(ctLog) - 1);
        Collections.swap(ctLogs, ctLogs.indexOf(ctLog), ctLogs.indexOf(previousCtLog));
    }

    /**
     * Moves the specified CT log down one step. This method does nothing if the CT log is already
     * on the bottom or if the CT log group to which the CT log belongs only contains one log.
     * @throws IllegalArgumentException if the CT log given as argument is not managed by this CT log manager
     */
    public void moveDown(final CTLogInfo ctLog) {
        final List<CTLogInfo> ctLogGroup = getCtLogsByLabel(ctLog.getLabel());
        if (!ctLogGroup.contains(ctLog)) {
            throw new IllegalArgumentException("The CT log " + ctLog.toString() + " is not managed by this CT log manager.");
        }
        if (ctLogGroup.size() == 1 || isOnBottom(ctLog)) {
            return;
        }
        final CTLogInfo nextCtLog = ctLogGroup.get(ctLogGroup.indexOf(ctLog) + 1);
        Collections.swap(ctLogs, ctLogs.indexOf(ctLog), ctLogs.indexOf(nextCtLog));
    }

    /**
     * Add a new CT log to this CT log manager. This method does not allow duplicates within the
     * same CT log group.
     * @param ctLog the CT log to add
     * @throws DuplicateCtLogException if the CT log already exists with the given label
     */
    public void addCtLog(final CTLogInfo ctLog) {
        if (!canAdd(ctLog)) {
            throw new DuplicateCtLogException("The CT log " + ctLog.toString() + " already exists in '" + ctLog.getLabel() + "'.");
        }
        ctLogs.add(ctLog);
    }

    /**
     * Removes an existing CT log from this log manager.
     * @param ctLog the CT log to remove
     * @throws IllegalArgumentException if the CT log is not managed by this CT log manager
     */
    public void removeCtLog(final CTLogInfo ctLog) {
        if (!ctLogs.contains(ctLog)) {
            throw new IllegalArgumentException("The CT log " + ctLog.toString() + " is not managed by this CT log manager.");
        }
        ctLogs.remove(ctLog);
    }

    /**
     * Determine whether the CT log given as input can be added to this CT log manager. A CT log cannot be added
     * if any of the following conditions hold for another CT log:
     * <ul>
     *   <li>The other log has an ID identical to the new CT log</li>
     *   <li>The other log is has an identical URL as the new CT log</li>
     * </ul>
     * @param the new CT log to check
     * @return true if the CT log given as input can be added, false otherwise
     */
    public boolean canAdd(final CTLogInfo ctLog) {
        for (CTLogInfo existing : ctLogs) {
            if (existing.getLogId() == ctLog.getLogId() || StringUtils.equals(existing.getUrl(), ctLog.getUrl())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Determine whether the CT log given as input is on the top in its CT log group.
     * @param ctLog the CT log to check
     * @return true iff the CT log is on the top in its CT log group
     */
    public boolean isOnTop(final CTLogInfo ctLog) {
        final List<CTLogInfo> ctLogGroup = getCtLogsByLabel(ctLog.getLabel());
        return !ctLogGroup.isEmpty() && ctLogGroup.get(0).equals(ctLog);
    }

    /**
     * Determine whether the CT log given as input is on the bottom in its CT log group.
     * @param ctLog the CT log to check
     * @return true iff the CT log is on the bottom in its CT log group
     */
    public boolean isOnBottom(final CTLogInfo ctLog) {
        final List<CTLogInfo> ctLogGroup = getCtLogsByLabel(ctLog.getLabel());
        return !ctLogGroup.isEmpty() && ctLogGroup.get(ctLogGroup.size() - 1).equals(ctLog);
    }

    /**
     * Rename a label. This will effectively set the label of CT logs to the
     * new label for every CT log with the old label.
     * @param oldLabel the label to change
     * @param newLabel the new label to set
     */
    public void renameLabel(final String oldLabel, final String newLabel) {
        for (CTLogInfo ctLog : ctLogs) {
            if (oldLabel.equals(ctLog.getLabel())) {
                ctLog.setLabel(newLabel);
            }
        }
    }

    /**
     * Returns the string representation of this object containing
     * the CT logs currently managed by this CT log manager.
     */
    @Override
    public String toString() {
        return "CT logs: " + getAllCtLogs().toString();
    }
}
