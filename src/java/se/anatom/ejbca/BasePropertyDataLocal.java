package se.anatom.ejbca;




/**
 * For docs, see BasePropertyEntityBean
 *
 * @version $Id: BasePropertyDataLocal.java,v 1.2 2004-01-25 09:37:10 herrvendil Exp $
 */
public interface BasePropertyDataLocal extends javax.ejb.EJBLocalObject {
    // Public methods
    public String getId();    
    public String getProperty();
    
    public String getValue();
    public void setValue(String value);
}
