package se.anatom.ejbca.ca.sign.junit;

import se.anatom.ejbca.ca.sign.*;
import se.anatom.ejbca.util.*;
import java.util.*;
import java.math.BigInteger;

import org.apache.log4j.*;
import junit.framework.*;


/** Tests generation of serial numbers.
 *
 * @version $Id: TestSernoGenerator.java,v 1.1 2002-08-20 12:18:23 anatom Exp $
 */
public class TestSernoGenerator extends TestCase {


    static Category cat = Category.getInstance( TestSernoGenerator.class.getName() );

    public TestSernoGenerator(String name) {
        super(name);
    }
    protected void setUp() throws Exception {
    }
    protected void tearDown() throws Exception {
    }

    /* Generates many serial numbers...
    */
    public void test01GenerateSernos() throws Exception {
        cat.debug(">test01GenerateSernos()");
        ISernoGenerator gen = SernoGenerator.instance();
        HashMap map = new HashMap(500000);
        String hex=null;
        for (int j=0;j<300;j++) {
            for (int i=0;i<1000;i++) {
                byte[] serno = gen.getSerno();
                if (serno.length != 8) {
                    System.out.println("Serno size != 8!!!");
                    break;
                }
                BigInteger bi = (new java.math.BigInteger(serno)).abs();
                //hex = Hex.encode(serno);
                hex = bi.toString();
                if (map.put(hex,hex) != null) {
                    System.out.println("Duplicate serno produced: "+hex);
                }
            }
            System.out.println((j+1)*1000+" sernos produced: "+hex);
        }
        System.out.println("Map now contains "+map.size()+" serial numbers.");
        cat.debug("<test01GenerateSernos()");
    }
}

