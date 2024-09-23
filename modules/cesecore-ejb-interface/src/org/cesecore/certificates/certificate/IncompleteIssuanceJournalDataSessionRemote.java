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
package org.cesecore.certificates.certificate;

import jakarta.ejb.Remote;

import org.cesecore.certificates.ca.IncompleteIssuanceJournalCallbacks;

/**
 * Used only for test
 * 
 **/
@Remote
public interface IncompleteIssuanceJournalDataSessionRemote extends IncompleteIssuanceJournalCallbacks {

}
