package se.anatom.ejbca.ca.caadmin;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a ca instance.
 * Information stored:
 * <pre>
 *  caid (Primary key)
 *  name
 *  SubjectDN
 *  type
 *  status
 *  expiretime
 *  data (non searchable data, HashMap stored as XML-String)
 * </pre>
 *
 * @version $Id: CADataBean.java,v 1.3 2004-03-03 16:18:05 herrvendil Exp $
 */
public abstract class CADataBean extends BaseEntityBean {

    private CA ca = null;

    private static Logger log = Logger.getLogger(CADataBean.class);

    public abstract Integer getCAId();
    public abstract void setCAId(Integer caid);

    public abstract String getName();
    public abstract void setName(String name);

    public abstract String getSubjectDN();
    public abstract void setSubjectDN(String subjectdn);
    
    public abstract int getStatus();
    public abstract void setStatus(int status);    
    
    public abstract long getExpireTime();
    public abstract void setExpireTime(long expiretime);    
    
    public abstract String getData();
    public abstract void setData(String data);    
    
    
    /** 
     * Method that retrieves the CA from the database.
     */    
    
    public CA getCA() throws java.io.UnsupportedEncodingException{
      if(ca == null){        
        java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(getData().getBytes("UTF8")));
        HashMap data = (HashMap) decoder.readObject();
        decoder.close();
             
        switch(((Integer)(data.get(CA.CATYPE))).intValue()){
            case CAInfo.CATYPE_X509:
              ca = (CA) new X509CA(data, getName(), getStatus(), new Date(getExpireTime()));
              break;
        }      
      }
      
      ca.setName(getName());
      ca.setStatus(getStatus());
      ca.setExpireTime(new Date(getExpireTime()));
      
      return ca;              
    }
    
    /** 
     * Method that saves the CA to database.
     */    
    public void setCA(CA ca)  throws java.io.UnsupportedEncodingException{        
       java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
       
       java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
       encoder.writeObject(ca.saveData());
       encoder.close();       
       setData(baos.toString("UTF8"));
       
       this.ca = ca;
    }   
    
    /**
     * Passivates bean, resets CA data.
     */
    public void ejbPassivate() {
        this.ca = null;
    }
    

    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a CA.
     * @param subjectdn.
     * @param name of CA
     * @param status initial status
     * @param CA CA to store
     * @return caid
     *
     **/

    public Integer ejbCreate(String subjectdn, String name, int status, CA ca) throws CreateException, java.io.UnsupportedEncodingException {
                
        setCAId(new Integer(subjectdn.hashCode()));
        setName(name);        
        setSubjectDN(subjectdn);
        setStatus(status);        
        
        
        if(ca instanceof X509CA && ca.getCertificateChain().size() != 0){
          setExpireTime(((X509Certificate) ca.getCACertificate()).getNotAfter().getTime());  
          ca.setExpireTime(((X509Certificate) ca.getCACertificate()).getNotAfter()); 
        }  
          
        setCA(ca);        
        log.debug("Created CA "+ name);
        return new Integer(subjectdn.hashCode());
    }

    public void ejbPostCreate(String subjectdn, String name, int status, CA ca) {
        // Do nothing. Required.
    }
    
    
}
