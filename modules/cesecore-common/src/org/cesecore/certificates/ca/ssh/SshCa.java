/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca.ssh;

import org.cesecore.certificates.ca.CA;

/**
 * General interface for SSH CAs
 *
 * @version $Id$
 */
public interface SshCa extends CA {

    String CA_TYPE = "SSHCA";

    Integer getSerialNumberOctetSize();
    void setCaSerialNumberOctetSize(int serialNumberOctetSize);

    boolean getUsePrintableStringSubjectDN();
    void setUsePrintableStringSubjectDN(boolean usePrintableStringSubjectDN);

    boolean getUseLdapDNOrder();
    void setUseLdapDNOrder(boolean useLdapDNOrder);

}
