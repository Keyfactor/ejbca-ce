package se.anatom.ejbca.util.passgen;
import java.util.Random;
import java.util.Date;

/**
 * BasePasswordGenerator is a baseclass for generating random passwords. 
 * Inheriting classes should overload the constants USEDCHARS, MIN_CHARS 
 * and MAX_CHARS.
 *
 * @version $Id: BasePasswordGenerator.java,v 1.2 2003-12-05 14:49:10 herrvendil Exp $
 */
public abstract class BasePasswordGenerator implements IPasswordGenerator{       
    
    protected BasePasswordGenerator(char[] usedchars){

       this.usedchars = usedchars; 
    }
    
	/**
	 * @see se.anatom.ejbca.util.passgen.IPasswordGenerator
	 */
    
	public String getNewPassword(int minlength, int maxlength){		
		int difference = maxlength - minlength;
		char[] password = null;
		
		Random ran = new Random((new Date()).getTime());
		
		// Calculate the length of password
		int passlen = minlength + ran.nextInt(difference);
		
		password = new char[passlen];
		for(int i=0; i < passlen; i++){
		  password[i] = usedchars[ran.nextInt(usedchars.length)];
		}					
		
		return new String(password);
	}
	
    
    private final char[] usedchars;
}
