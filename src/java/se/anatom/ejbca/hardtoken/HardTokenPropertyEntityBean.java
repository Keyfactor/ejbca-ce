package se.anatom.ejbca.hardtoken;

import se.anatom.ejbca.BasePropertyEntityBean;



/**
 * HardTokenPropertyEntityBean is a complientary class used to assign extended
 * properties like copyof to a hard token.
 * 
 * Id is represented by primary key of hard token table.
 *
 * @version $Id: HardTokenPropertyEntityBean.java,v 1.0 2003/12/12 21:37:16 herrvendil Exp 
 */
public abstract class HardTokenPropertyEntityBean extends BasePropertyEntityBean {

  public static final String PROPERTY_COPYOF = "copyof=";
    
}
