package se.anatom.ejbca.ca.store;

import java.io.Serializable;
import java.util.Date;

/**
 * Holds information about a CRL but not he CRL itself.
 *
 * @version $Id: CRLInfo.java,v 1.1 2003-09-03 19:45:50 herrvendil Exp $
 */
public class CRLInfo implements Serializable {
    
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
