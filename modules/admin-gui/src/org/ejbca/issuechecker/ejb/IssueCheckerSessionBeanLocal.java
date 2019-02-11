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

package org.ejbca.issuechecker.ejb;

import java.util.Set;
import java.util.stream.Stream;

import javax.ejb.Local;

import org.ejbca.issuechecker.Issue;
import org.ejbca.issuechecker.IssueSet;
import org.ejbca.issuechecker.Ticket;

/**
 * Methods for the issue checker available locally.
 *
 * @version $Id$
 */
@Local
public interface IssueCheckerSessionBeanLocal {

    /**
     * Get a stream of tickets present on the system. The stream is filtered based
     * on the enabled issue sets and is sorted based on priority, with the most urgent
     * issues first.
     *
     * @return a filtered and sorted stream of tickets.
     */
    Stream<Ticket> getTickets();

    /**
     * Get a set of all implemented issues.
     *
     * @return a set of all implemented issues.
     */
    Set<Issue> getAllIssues();

    /**
     * Get a set of all implemented issue sets.
     *
     * @return a set of all implemented issue sets.
     */
    Set<IssueSet> getAllIssueSets();
}
