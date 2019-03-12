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
package org.cesecore.certificates.crl;

import java.io.Serializable;
import java.util.Date;

/**
 * Holds information about a CRL but not he CRL itself.
 *
 * @version $Id$
 */
public final class CRLInfo implements Serializable {

    private static final long serialVersionUID = 4942836797714142516L;
    private final String subjectdn;
    private final int crlPartitionIndex;
    private final int lastcrlnumber;
    private final Date thisupdate;
    private final Date nextupdate;

    public CRLInfo(final String subjectdn, final int crlPartitionIndex, final int lastcrlnumber, final long thisupdate, final long nextupdate) {
      this.subjectdn = subjectdn;
      this.crlPartitionIndex = crlPartitionIndex;
      this.lastcrlnumber = lastcrlnumber;
      this.thisupdate = new Date(thisupdate);
      this.nextupdate = new Date(nextupdate);
    }

    /** Subject DN of CA that we have queried information for */
    public String getSubjectDN() {return subjectdn;}
    /** CRL partition that we have queried information for, or CertificateConstants.NO_CRL_PARTITION for the main CRL */
    public int getCrlPartitionIndex() { return crlPartitionIndex; }

    public int getLastCRLNumber() { return lastcrlnumber; }
    public Date getCreateDate() { return thisupdate; }
    public Date getExpireDate() { return nextupdate; }
}
