package se.anatom.ejbca;




/**
 * For docs, see BasePropertyEntityBean
 *
 * @version $Id: BasePropertyDataLocal.java,v 1.1 2004-01-08 14:31:26 herrvendil Exp $
 */
public interface BasePropertyDataLocal extends javax.ejb.EJBLocalObject {
    // Public methods
    public int getId();    
    public String getProperty();
    
    public String getValue();
    public void setValue(String value);
}
