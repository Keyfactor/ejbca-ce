package se.anatom.ejbca.util;

import junit.framework.TestCase;

import javax.ejb.EJBLocalHome;
import javax.ejb.RemoveException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import java.util.HashMap;

/**
 * Test for the SimpleSequenceGenerator.
 *
 * Make sure that it works...somewhat. :)
 */
public class TestSimpleSequenceGenerator extends TestCase {

    private final static int IT = 100000;

    public void testUnableToFindFreeID() throws Exception {
        try {
            // use a map that always return non null to fake that it always find an existing id
            HashMap map = new HashMap() {
                public Object get(Object key) {
                    return "dummy";
                }
            };
            EJBLocalHome home = new TestLocalHome(map);
            SimpleSequenceGenerator.getNextCount( home );
            fail("Should generate an EJBException when no free ID");
        } catch (EJBException e){
            assertNull("Should be a clean EJBException", e.getCause());
        }
    }

    public void testAbletoFindFreeID() throws Exception {
        EJBLocalHome home = new TestLocalHome(new HashMap()); // will throw a FindExceptionInternally == Free ID
        Integer id = SimpleSequenceGenerator.getNextCount( home );
        assertNotNull(id);
    }

    public void testGenerateMultipleConsecutiveIDs() throws Exception {
        HashMap db = new HashMap();
        EJBLocalHome home = new TestLocalHome(db);
        for (int i = 0; i < IT; i++) {
            Integer id = SimpleSequenceGenerator.getNextCount( home );
            db.put(id, "dummy"); // simulate a database with stored ids
        }
        // check that it is really not duplicate ids
        assertEquals(IT, db.size());
    }

    public void testGenerateMultipleFailedConsecutiveIDs() throws Exception {
        // use a map that always return non null to fake that it always find an existing id
        HashMap db = new HashMap() {
            public Object get(Object key) {
                return "dummy";
            }
        };
        EJBLocalHome home = new TestLocalHome(db);
        for (int i = 0; i < IT; i++) {
            try {
                Integer id = SimpleSequenceGenerator.getNextCount( home );
                id.intValue();
            } catch (EJBException e){
            }
        }
    }

    public void testInvalidFinderMethod() throws Exception {
        EJBLocalHome home = new EJBLocalHome(){
            public Object findByPrimaryKey(String pk) { return ""; }
            public void remove(Object o) throws RemoveException, EJBException {}
        };
        try {
            SimpleSequenceGenerator.getNextCount(home);
            fail("Expected a wrapped NoSuchMethodException");
        } catch (EJBException e){
            assertNotNull(e.getCausedByException());
            assertEquals(NoSuchMethodException.class, e.getCausedByException().getClass());
        }
    }

    public static class TestLocalHome implements EJBLocalHome {
        private HashMap map;
        public TestLocalHome(HashMap map){
            this.map = map;
        }
        public Object findByPrimaryKey(Integer pk) throws FinderException {
            Object o = map.get(pk);
            if (o == null) throw new FinderException("thrown on purpose to simulate non existing object");
            return o;
        }
        public void remove(Object o) throws RemoveException, EJBException {
        }
    }

}