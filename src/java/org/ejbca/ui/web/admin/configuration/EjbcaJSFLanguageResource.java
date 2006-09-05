package org.ejbca.ui.web.admin.configuration;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJBException;

import org.ejbca.util.HTMLTools;

/**
 * Class used to retrieve EJBCA language resources in JSF views
 * 
 * Implements a Map used for retrieving resources.
 * @author Philip Vendil
 * $id$
 */
public class EjbcaJSFLanguageResource implements Map {

	private EjbcaWebBean ejbcawebbean;
	
	public EjbcaJSFLanguageResource(EjbcaWebBean ejbcawebbean){
		this.ejbcawebbean = ejbcawebbean;
	}
	
	public void clear() {
		throw new EJBException("Method clear not supported");
	}

	public boolean containsKey(Object arg0) {
		
		return ejbcawebbean.getText((String) arg0) != null;
	}

	public boolean containsValue(Object arg0) {
		throw new EJBException("Method containsValue not supported");
	}

	public Set entrySet() {
		throw new EJBException("Method entrySet not supported");
	}

	public Object get(Object arg0) {
		String str = ejbcawebbean.getText((String) arg0);
		return HTMLTools.htmlunescape(str);
	}

	public boolean isEmpty() {
		throw new EJBException("Method isEmpty not supported");
	}

	public Set keySet() {
		throw new EJBException("Method keySet not supported");
	}

	public Object put(Object arg0, Object arg1) {
		throw new EJBException("Method put not supported");
	}

	public void putAll(Map arg0) {
		throw new EJBException("Method putAll not supported");
	}

	public Object remove(Object arg0) {
		throw new EJBException("Method remove not supported");
	}

	public int size() {
		throw new EJBException("Method size not supported");
	}

	public Collection values() {
		throw new EJBException("Method values not supported");
	}

}
