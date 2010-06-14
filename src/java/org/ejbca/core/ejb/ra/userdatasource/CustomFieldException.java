package org.ejbca.core.ejb.ra.userdatasource;

public class CustomFieldException extends Exception {

	private static final long serialVersionUID = -4270699717178908309L;

	public CustomFieldException(){
		super();
	}
	
	public CustomFieldException(String message){
		super(message);
	}
	
	public CustomFieldException(Throwable cause){
		super(cause);
	}
	
	public CustomFieldException(String message, Throwable cause){
		super(message, cause);
	}
}
