package javax.ejb;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
/**
 * clientToolbox is not an EJB but when building it ejbca classes that is using 
 * this interface are compiled. This file is just here to be used when compiling
 * clientToolBox so we don't have to use any ejb jar.
 *  
 * @version $Id$
*/
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface ApplicationException
{
    /**
     * Indicates whether the container should cause the transaction to rollback when the
     * exception is thrown.
     */
    boolean rollback() default false;
}
