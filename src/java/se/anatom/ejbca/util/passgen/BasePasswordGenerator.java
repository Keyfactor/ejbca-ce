package se.anatom.ejbca.util.passgen;
import java.util.Random;
import java.util.Date;

/**
 * BasePasswordGenerator is a baseclass for generating random passwords. 
 * Inheriting classes should overload the constants USEDCHARS, MIN_CHARS 
 * and MAX_CHARS.
 *
 * @version $Id: BasePasswordGenerator.java,v 1.3 2004-01-31 14:25:00 herrvendil Exp $
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
		int passlen = maxlength;
		if(minlength != maxlength)
		  passlen = minlength + ran.nextInt(difference);
		
		password = new char[passlen];
		for(int i=0; i < passlen; i++){
		  password[i] = usedchars[ran.nextInt(usedchars.length)];
		}					
		
		return new String(password);
	}
	
    
    private final char[] usedchars;
}
