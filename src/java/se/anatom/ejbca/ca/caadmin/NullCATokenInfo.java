package se.anatom.ejbca.ca.caadmin;

import java.io.Serializable;

/**
 * Holds nonsensitive information about a null CAToken. Used by processed external CAs not having any keys.
 *
 * @version $Id: NullCATokenInfo.java,v 1.1 2003-10-21 13:48:45 herrvendil Exp $
 */
public class NullCATokenInfo extends CATokenInfo implements Serializable {    
       
    public NullCATokenInfo(){}
    

}
