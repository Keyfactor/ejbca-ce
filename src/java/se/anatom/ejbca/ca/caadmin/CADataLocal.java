package se.anatom.ejbca.ca.caadmin;


/**
 * For docs, see CADataBean
 *
 * @version $Id: CADataLocal.java,v 1.1 2003-09-03 16:21:29 herrvendil Exp $
 **/

public interface CADataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getCAId();
    
    public String getName();
    public void setName(String name);

    public String getSubjectDN();
    
    public int getStatus();
    public void setStatus(int status);    
    
    public long getExpireTime();
    public void setExpireTime(long expiretime);    

    public CA getCA() throws java.io.UnsupportedEncodingException;
    public void setCA(CA ca) throws java.io.UnsupportedEncodingException;    
    
    
}

