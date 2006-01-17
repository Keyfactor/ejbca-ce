package org.ejbca.util;

import javax.ejb.EJBLocalHome;
import javax.ejb.FinderException;
import javax.ejb.EJBException;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.util.Random;

/**
 * A very simple sequence generator. It is just intended for test purpose and if
 * possible you should avoid to use it in production.
 *
 * I just adapted it from what was used inside an EJB to get something more generic.
 * Ideally a more full featured sequence generator should be used such as the one
 * from OpenSymphony OSCore or from EJB Design Pattern.
 *
 */
public class SimpleSequenceGenerator {

    /** the random generator */
    private static final Random RAND = new Random();

    /**
     * This method is just plain brain dead and basically assumes a findPrimaryKey(Integer) on the
     * home interface, it will then attempts to find an available primary key slot by generating
     * random numbers. Please refrain from using it but for prototyping.
     * @param home the home interface to find the findPrimaryKey (it must obviouslly be an entity bean)
     * @return the valid integer object to be used as a primary key
     * @throws EJBException if it failed to generate a valid primary key
     */
    public static Integer getNextCount(EJBLocalHome home) throws EJBException {
        // use reflection to invoke findByPrimaryKey
        Class c = home.getClass();
        try {
            Method m = c.getDeclaredMethod("findByPrimaryKey", new Class[]{ Integer.class } );
            int maxAttempts = 10;
            while (maxAttempts >= 0){
                Integer id = getNextInt();
                try {
                    m.invoke(home, new Object[]{ id });
                } catch (InvocationTargetException e){
                    // if there is a finder exception it means there is no object with that key
                    // and thus that the slot is free.
                    if (e.getCause() instanceof FinderException){
                        return id;
                    }
                    throw e;
                }
                maxAttempts--;
            }
        } catch (Exception e){
            throw new EJBException(e);
        }
        throw new EJBException("Failed to generate a unique id for home " + home.getClass().getName());
    }

    /**
     * Random is not thread safe, so minimize contention here.
     * @return the Random.nextInt as an Integer object
     */
    private static final Integer getNextInt() {
        synchronized(RAND){
            return new Integer(RAND.nextInt());
        }
    }
}
