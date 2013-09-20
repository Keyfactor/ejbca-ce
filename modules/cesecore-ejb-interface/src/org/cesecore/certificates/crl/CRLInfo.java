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
public class CRLInfo implements Serializable {
    
    private static final long serialVersionUID = 4942836797714142516L;
    protected String subjectdn;
    protected int lastcrlnumber;
    protected Date thisupdate;
    protected Date nextupdate;
    
    public CRLInfo(String subjectdn, int lastcrlnumber, long thisupdate, long nextupdate){
      this.subjectdn = subjectdn;
      this.lastcrlnumber = lastcrlnumber;
      this.thisupdate = new Date(thisupdate);
      this.nextupdate = new Date(nextupdate);
    }
    
    public String getSubjectDN() {return subjectdn;}
    public int getLastCRLNumber() { return lastcrlnumber; }
    public Date getCreateDate() { return thisupdate; }
    public Date getExpireDate() { return nextupdate; }
    
}
