package se.anatom.ejbca.util.passgen;
import java.util.Random;
import java.util.Date;

/**
 * BasePasswordGenerator is a baseclass for generating random passwords. 
 * Inheriting classes should overload the constants USEDCHARS, MIN_CHARS 
 * and MAX_CHARS.
 *
 * @version $Id: BasePasswordGenerator.java,v 1.1 2003-10-21 13:48:47 herrvendil Exp $
 */
public abstract class BasePasswordGenerator implements IPasswordGenerator{       
    
    protected BasePasswordGenerator(int minlength, int maxlength, char[] usedchars){
       this.minlength  = minlength;
       this.difference = maxlength - minlength;
       this.usedchars = usedchars; 
    }
    
	/**
	 * @see se.anatom.ejbca.util.passgen.IPasseordGenerator
	 */
    
	public String getNewPassword(){
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
	
    
    private final int minlength;    
    private final int difference;
    private final char[] usedchars;
}
