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

package org.ejbca.ui.web.protocol;

import org.ejbca.core.protocol.certificatestore.CertStoreStandAlone;
import org.ejbca.core.protocol.crlstore.CRLStoreStandAlone;


/** 
 * Servlet implementing server side of the Certificate Store.
 * For a detailed description see rfc4378.
 *
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
public class CRLStoreServletStandAlone extends CRLStoreServletBase {
	public CRLStoreServletStandAlone() {
		super( new CertStoreStandAlone(), new CRLStoreStandAlone() );
	}
} // CRLStoreServletStandAlone
