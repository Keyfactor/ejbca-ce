package se.anatom.ejbca.util;

import java.util.HashMap;

import javax.ejb.EJBException;
import javax.ejb.EJBLocalHome;

import junit.framework.TestCase;

/**
 * Test for the SimpleSequenceGenerator.
 *
 * Make sure that it works...somewhat. :)
 */
public class TestSimpleSequenceGenerator extends TestCase {

    private final static int IT = 100000;

    /**
     * Creates a new TestSimpleSequenceGenerator object.
     *
     * @param name DOCUMENT ME!
     */
    public TestSimpleSequenceGenerator(String name) {
        super(name);
    }

    public void testUnableToFindFreeID() throws Exception {
        try {
            // use a map that always return non null to fake that it always find an existing id
            HashMap map = new DummyHashMap();
            EJBLocalHome home = new DummyLocalHome(map);
            SimpleSequenceGenerator.getNextCount( home );
            fail("Should generate an EJBException when no free ID");
        } catch (EJBException e){
            assertNull("Should be a clean EJBException", e.getCause());
        }
    }

    public void testAbletoFindFreeID() throws Exception {
        EJBLocalHome home = new DummyLocalHome(new HashMap()); // will throw a FindExceptionInternally == Free ID
        Integer id = SimpleSequenceGenerator.getNextCount( home );
        assertNotNull(id);
    }

    public void testGenerateMultipleConsecutiveIDs() throws Exception {
        HashMap db = new HashMap();
        EJBLocalHome home = new DummyLocalHome(db);
        for (int i = 0; i < IT; i++) {
            Integer id = SimpleSequenceGenerator.getNextCount( home );
            db.put(id, "dummy"); // simulate a database with stored ids
        }
        // check that it is really not duplicate ids
        assertEquals(IT, db.size());
    }

    public void testGenerateMultipleFailedConsecutiveIDs() throws Exception {
        // use a map that always return non null to fake that it always find an existing id
        HashMap db = new DummyHashMap();
        EJBLocalHome home = new DummyLocalHome(db);
        for (int i = 0; i < IT; i++) {
            try {
                Integer id = SimpleSequenceGenerator.getNextCount( home );
                id.intValue();
            } catch (EJBException e){
            }
        }
    }
}