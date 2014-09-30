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
package org.ejbca.util.cert;

import java.security.cert.Certificate;
import java.util.Comparator;
import java.util.Date;

import org.cesecore.util.CertTools;

/** Simple comparator comparing two certificates for NotBefore date.
 * if arg0 have a NotBefore that is after arg1, arg0 is less than arg1.
 * 
 * @author tomas
 * @version $Id$
 */
public class CertificateNotBeforeComparator implements Comparator<Certificate> {

	/** Compared NotBefore field of arg0 and arg1 if they are both instances of java.security.cert.Certificate
	 * @return -1 if NotBefore in arg0 is after BotBefore in arg1, +1 if reverse and 0 if NotBefore is exactly the same.
	 */
	public int compare(Certificate arg0, Certificate arg1) {
		// We don't have to check instanceof here because the Comparator javadoc says that it is supposed to throw ClassCastException
		// if the types are wrong.
		Certificate cert1 = (Certificate) arg1;
		Certificate cert0 = (Certificate) arg0;
		Date d0 = CertTools.getNotBefore(cert0);
		Date d1 = CertTools.getNotBefore(cert1);
		if (d0.before(d1)) {
			return 1;
		}
		if (d0.after(d1)) {
			return -1;
		}
		return 0;
	}
}
