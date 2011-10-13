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
package org.ejbca.core.ejb.ca.publisher;

import java.security.cert.Certificate;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherException;

/**
 * Local interface for PublisherQueueSession.
 * @version $Id$
 */
@Local
public interface PublisherQueueSessionLocal extends PublisherQueueSession {

    /** Publishers do not run a part of regular transactions and expect to run in auto-commit mode. */
	public boolean storeCertificateNonTransactional(BasePublisher publisher, AuthenticationToken admin, Certificate cert, String username, String password, String userDN,
    		String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId,
    		long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException;

    /** Publishers do not run a part of regular transactions and expect to run in auto-commit mode. */
	public boolean storeCRLNonTransactional(BasePublisher publisher, AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException;

    /** Publishers digest queues in transaction-based "chunks". */
	int doChunk(AuthenticationToken admin, int publisherId, BasePublisher publisher);
}
