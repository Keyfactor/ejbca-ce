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

import javax.ejb.Remote;

/**
 * Remote interface for ProtectedLogSession.
 * 
 * @deprecated
 */
@Remote
public interface ProtectedLogSessionRemote {
    /**
     * Persists a new token to the database.
     */
    public void addToken(org.ejbca.core.model.log.IProtectedLogToken token) throws java.rmi.RemoteException;

    /**
     * Fetch a existing token from the database. Caches the last found token.
     * 
     * @return null if no token was found
     */
    public org.ejbca.core.model.log.IProtectedLogToken getToken(int tokenIdentifier) throws java.rmi.RemoteException;

    /**
     * Find and remove all the specified tokens.
     */
    public void removeTokens(java.lang.Integer[] tokenIdentifiers) throws java.rmi.RemoteException;

    /**
     * Persists a new export to the database.
     */
    public void addExport(org.ejbca.core.model.log.ProtectedLogExportRow protectedLogExportRow) throws java.rmi.RemoteException;

    public org.ejbca.core.model.log.ProtectedLogExportRow getLastExport() throws java.rmi.RemoteException;

    public org.ejbca.core.model.log.ProtectedLogExportRow getLastSignedExport() throws java.rmi.RemoteException;

    /**
     * Persist a new ProtectedLogEvent
     */
    public void addProtectedLogEventRow(org.ejbca.core.model.log.ProtectedLogEventRow protectedLogEventRow) throws java.rmi.RemoteException;

    public org.ejbca.core.model.log.ProtectedLogEventRow getProtectedLogEventRow(org.ejbca.core.model.log.ProtectedLogEventIdentifier identifier)
            throws java.rmi.RemoteException;

    /**
     * Find the newest event for all nodes, except the specified node.
     */
    public org.ejbca.core.model.log.ProtectedLogEventIdentifier[] findNewestProtectedLogEventsForAllOtherNodes(int nodeToExclude, long newerThan)
            throws java.rmi.RemoteException;

    public org.ejbca.core.model.log.ProtectedLogEventIdentifier findNewestProtectedLogEventRow(int nodeGUID) throws java.rmi.RemoteException;

    public org.ejbca.core.model.log.ProtectedLogEventIdentifier findNewestLogEventRow(int nodeGUID) throws java.rmi.RemoteException;

    public org.ejbca.core.model.log.ProtectedLogEventIdentifier findNewestProtectedLogEventRow() throws java.rmi.RemoteException;

    public org.ejbca.core.model.log.ProtectedLogEventIdentifier findNewestProtectedLogEventRow(boolean isProtected) throws java.rmi.RemoteException;

    /**
     * Find the oldest log-event, protected or unprotected
     */
    public org.ejbca.core.model.log.ProtectedLogEventIdentifier findOldestProtectedLogEventRow() throws java.rmi.RemoteException;

    public java.lang.Integer[] getNodeGUIDs(long exportStartTime, long exportEndTime) throws java.rmi.RemoteException;

    public java.lang.Integer[] getAllNodeGUIDs() throws java.rmi.RemoteException;

    /**
     * Find all nodeGUIDs where all log events are unprotected.
     */
    public java.lang.Integer[] getFullyUnprotectedNodeGUIDs() throws java.rmi.RemoteException;

    public org.ejbca.core.model.log.ProtectedLogEventRow[] findNextProtectedLogEventRows(long exportStartTime, long exportEndTime, int fetchSize)
            throws java.rmi.RemoteException;

    /**
     * Deletes all log events until the reqeusted time
     */
    public void removeAllUntil(long exportEndTime) throws java.rmi.RemoteException;

    /**
     * Testing function. Removes all log-events belonging to a nodeGUID.
     */
    public void removeNodeChain(int nodeGUID) throws java.rmi.RemoteException;

    /**
     * Roll back the export table to the last one with the delete-flag set. This
     * will remove all the export if none has the delet-flag set.
     */
    public boolean removeAllExports(boolean removeDeletedToo) throws java.rmi.RemoteException;

    /**
     * Retrieve a list of token the has been used before, but not after the
     * request time.
     */
    public java.lang.Integer[] findTokenIndentifiersUsedOnlyUntil(long exportEndTime) throws java.rmi.RemoteException;

    /**
     * Verifies that the certificate was valid at the time of signing and that
     * the signature was made by the owner of this certificate.
     */
    public boolean verifySignature(byte[] data, byte[] signature, java.security.cert.Certificate certificate, long timeOfSigning)
            throws java.rmi.RemoteException;

    /**
     * Verifies that the certificate was valid at the specified time
     */
    public boolean verifyCertificate(java.security.cert.Certificate certificate, long timeOfUse) throws java.rmi.RemoteException;

    /**
     * Perform a query and convert to a Collection of LogEntry
     */
    public java.util.Collection performQuery(java.lang.String sqlQuery, int maxResults) throws java.rmi.RemoteException;

    /**
     * Iterates forward in time, verifying each hash of the previous event until
     * a signature is reached which is verified.
     * 
     * @return -1 on failure, 0 if undetermined, 1 if successful
     */
    public int verifyProtectedLogEventRow(org.ejbca.core.model.log.ProtectedLogEventRow protectedLogEventRow, boolean checkVerifiedSteps)
            throws java.rmi.RemoteException;

    /**
     * Verify entire log Verify that log hasn't been frozen for any node Verify
     * that each protect operation had a valid certificate and is not about to
     * expire without a valid replacement Verify that no nodes exists that
     * haven't been processed Starts at the specified event and traverses
     * through the chain of linked in events, following one nodeGUID at the
     * time. The newest signature for each node is verifed and the link-in
     * hashes for each event. The verification continues node by node, until the
     * oldest event is reached or the time where an verified exporting delete
     * was last made.
     * 
     * @param freezeThreshold
     *            longest allowed time to newest ProtectedLogEvent of any node
     *            (milliseconds)
     * @return null if log verification was ok, a ProtectedLogEventIdentifier
     *         for the row where verification failed if verification failed.
     */
    public org.ejbca.core.model.log.ProtectedLogEventIdentifier verifyEntireLog(int actionType, long freezeThreshold) throws java.rmi.RemoteException;

    /**
     * Fetches a known token from the database or creates a new one, depending
     * on the configuration.
     */
    public org.ejbca.core.model.log.IProtectedLogToken getProtectedLogToken() throws java.rmi.RemoteException;

    /**
     * Insert a new signed stop event for each unsigned node-chain in a
     * "near future" and let the real node chain in these events..
     * 
     * @param signAll
     *            is true if all unprotected chains should be signed, not just
     *            frozen ones
     */
    public boolean signAllUnsignedChains(boolean signAll) throws java.rmi.RemoteException;

    /**
     * Create a new signed log event that links in unsigned log chain identified
     * by nodeGUID
     * 
     * @param nodeGUID
     *            the nodeGUID to accept and link in
     * @return true if ok, false if MessageDigest cannot be created of any
     *         signed log events could not be found (if
     *         newestProtectedLogEventRow is null)
     */
    public boolean signUnsignedChainUsingSingleSignerNode(java.lang.Integer nodeGUID) throws java.rmi.RemoteException;

    public boolean signUnsignedChain(org.ejbca.core.model.log.ProtectedLogEventRow newestProtectedLogEventRow, java.lang.Integer nodeGUID)
            throws java.rmi.RemoteException;

    /**
     * Optionally exports and then deletes the entire log and export table.
     * Writes an export to the database with the deleted events' times
     */
    public boolean resetEntireLog(boolean export) throws java.rmi.RemoteException;

    /**
     * Temporary halts the verification and export services
     * 
     * @return true if successful
     */
    public boolean stopServices() throws java.rmi.RemoteException;

    /**
     * Restarts the verification and export services
     */
    public void startServices() throws java.rmi.RemoteException;

    /**
     * Exports the log the the given export handler and stores a signed hash
     * linking each export to the last one.
     */
    public boolean exportLog(org.ejbca.core.model.log.IProtectedLogExportHandler protectedLogExportHandler, int actionType,
            java.lang.String currentHashAlgorithm, boolean deleteAfterExport, long atLeastThisOld) throws java.rmi.RemoteException;

    public boolean existsAnyProtectedLogEventByTime(long time) throws java.rmi.RemoteException;
}
