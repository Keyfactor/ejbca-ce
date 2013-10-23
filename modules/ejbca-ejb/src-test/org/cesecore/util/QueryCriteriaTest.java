/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import java.util.Date;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.QueryGenerator;
import org.junit.Assert;
import org.junit.Test;

/**
 * Verify that queries are generated dynamically as expected.
 * 
 * @version $Id$
 */
public class QueryCriteriaTest {

    private static Logger log = Logger.getLogger(QueryCriteriaTest.class);

	private static final String BAD_QUERY_GENERATED = "Invalid query generated.";
	private static final String BAD_QUERY_PARAMTERS = "Invalid paramter values stored in query.";
	private static final String DUMMY_VALUE_STR1 = "dummyValue1";
	private static final String DUMMY_VALUE_STR2 = "dummyValue2";
	private static final int DUMMY_VALUE_INT1 = 01234;
	private static final int DUMMY_VALUE_INT2 = 56789;

	public class FakeEntity {
		static final String FIELDNAME1 = "field1";
		static final String FIELDNAME2 = "field2";
		String field1;
		int field2;
	}
	
    /** Test the ability to detect if valid parameters are used. */
    @Test
    public void testBadParameterQuery() {
        try {
            QueryCriteria criteria = QueryCriteria.create().add(Criteria.eq(FakeEntity.FIELDNAME1, "value"));
            QueryGenerator.generator(FakeEntity.class, criteria, "a").generate();
        } catch (QueryParameterException e) {
            log.error("QueryCriteria unable to detect existing field.", e);
            Assert.fail("QueryCriteria unable to detect existing field.");
        }
        try {
            QueryCriteria criteria = QueryCriteria.create().add(Criteria.eq("invalidParameterName", "value"));
            QueryGenerator.generator(FakeEntity.class, criteria, "a").generate();
            Assert.fail("QueryCriteria unable to detect non-existing field.");
        } catch (QueryParameterException e) {
            // Expected
        }
    }

    @Test
    public void testBasicQuery() {
        // This is the behavior.. perhaps it would be better to not return the "WHERE" clause when no parameters are present..
        final QueryCriteria qc = QueryCriteria.create();
        QueryGenerator generator = QueryGenerator.generator(FakeEntity.class, qc, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, "", generator.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, generator.getParameterKeys().size());
    }

    @Test
    public void testBasicQueryEqual() {
        final QueryCriteria qc1 = QueryCriteria.create().add(Criteria.eq(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1));
        QueryGenerator generator1 = QueryGenerator.generator(FakeEntity.class, qc1, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 = :field10", generator1.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, generator1.getParameterKeys().size());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, generator1.getParameterValue(generator1.getParameterKeys().iterator().next()));
        final QueryCriteria qc2 = QueryCriteria.create().add(Criteria.eq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1));
        QueryGenerator generator2 = QueryGenerator.generator(FakeEntity.class, qc2, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 = :field20", generator2.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, generator2.getParameterKeys().size());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, generator2.getParameterValue(generator2.getParameterKeys().iterator().next()));
    }

    @Test
    public void testBasicQueryGreaterOrEqual() {
        final QueryCriteria qc = QueryCriteria.create().add(Criteria.geq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1));
        QueryGenerator generator = QueryGenerator.generator(FakeEntity.class, qc, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 >= :field20", generator.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, generator.getParameterKeys().size());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, generator.getParameterValue(generator.getParameterKeys().iterator().next()));
    }

    @Test
    public void testBasicQueryLessOrEqual() {
        final QueryCriteria qc = QueryCriteria.create().add(Criteria.leq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1));
        QueryGenerator generator = QueryGenerator.generator(FakeEntity.class, qc, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 <= :field20", generator.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, generator.getParameterKeys().size());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, generator.getParameterValue(generator.getParameterKeys().iterator().next()));
    }

    @Test
    public void testBasicQueryBetween() {
        final QueryCriteria qc1 = QueryCriteria.create().add(Criteria.between(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1, DUMMY_VALUE_STR2));
        QueryGenerator generator1 = QueryGenerator.generator(FakeEntity.class, qc1, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 BETWEEN :field10 AND :field11", generator1.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 2, generator1.getParameterKeys().size());
        final Iterator<String> i1 = generator1.getParameterKeys().iterator();
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, generator1.getParameterValue(i1.next()));
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR2, generator1.getParameterValue(i1.next()));
        final QueryCriteria qc2 = QueryCriteria.create().add(Criteria.between(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1, DUMMY_VALUE_INT2));
        QueryGenerator generator2 = QueryGenerator.generator(FakeEntity.class, qc2, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 BETWEEN :field20 AND :field21", generator2.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 2, generator2.getParameterKeys().size());
        final Iterator<String> i2 = generator2.getParameterKeys().iterator();
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, generator2.getParameterValue(i2.next()));
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT2, generator2.getParameterValue(i2.next()));
    }

    @Test
    public void testBasicQueryLike() {
        final QueryCriteria qc = QueryCriteria.create().add(Criteria.like(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1));
        QueryGenerator generator = QueryGenerator.generator(FakeEntity.class, qc, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 LIKE :field10", generator.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, generator.getParameterKeys().size());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, generator.getParameterValue(generator.getParameterKeys().iterator().next()));
    }

    @Test
    public void testBasicQueryLess() {
        final QueryCriteria qc = QueryCriteria.create().add(Criteria.lsr(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1));
        QueryGenerator generator = QueryGenerator.generator(FakeEntity.class, qc, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 < :field20", generator.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, generator.getParameterKeys().size());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, generator.getParameterValue(generator.getParameterKeys().iterator().next()));
    }

    @Test
    public void testBasicQueryGreater() {
        final QueryCriteria qc = QueryCriteria.create().add(Criteria.grt(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1));
        QueryGenerator generator = QueryGenerator.generator(FakeEntity.class, qc, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 > :field20", generator.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, generator.getParameterKeys().size());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, generator.getParameterValue(generator.getParameterKeys().iterator().next()));
    }

    @Test
    public void testBasicQueryNotEqual() {
        final QueryCriteria qc1 = QueryCriteria.create().add(Criteria.neq(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1));
        QueryGenerator generator1 = QueryGenerator.generator(FakeEntity.class, qc1, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 != :field10", generator1.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, generator1.getParameterKeys().size());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, generator1.getParameterValue(generator1.getParameterKeys().iterator().next()));
        final QueryCriteria qc2 = QueryCriteria.create().add(Criteria.neq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1));
        QueryGenerator generator2 = QueryGenerator.generator(FakeEntity.class, qc2, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 != :field20", generator2.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, generator2.getParameterKeys().size());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, generator2.getParameterValue(generator2.getParameterKeys().iterator().next()));
    }

    @Test
    public void testBasicQueryNotNull() {
        final QueryCriteria qc1 = QueryCriteria.create().add(Criteria.isNotNull(FakeEntity.FIELDNAME1));
        QueryGenerator generator1 = QueryGenerator.generator(FakeEntity.class, qc1, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 IS NOT NULL", generator1.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, generator1.getParameterKeys().size());
        final QueryCriteria qc2 = QueryCriteria.create().add(Criteria.isNotNull(FakeEntity.FIELDNAME2));
        QueryGenerator generator2 = QueryGenerator.generator(FakeEntity.class, qc2, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 IS NOT NULL", generator2.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, generator2.getParameterKeys().size());
    }

    @Test
    public void testBasicQueryNull() {
        final QueryCriteria qc1 = QueryCriteria.create().add(Criteria.isNull(FakeEntity.FIELDNAME1));
        QueryGenerator generator1 = QueryGenerator.generator(FakeEntity.class, qc1, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 IS NULL", generator1.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, generator1.getParameterKeys().size());
        final QueryCriteria qc2 = QueryCriteria.create().add(Criteria.isNull(FakeEntity.FIELDNAME2));
        QueryGenerator generator2 = QueryGenerator.generator(FakeEntity.class, qc2, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 IS NULL", generator2.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, generator2.getParameterKeys().size());
    }

    @Test
    public void testCombinedQueryEqual() {
        // Or
        final QueryCriteria qc1 = QueryCriteria.create().add(Criteria.or(Criteria.eq(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1),Criteria.eq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1)));
        QueryGenerator generator1 = QueryGenerator.generator(FakeEntity.class, qc1, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 = :field10 OR a.field2 = :field20", generator1.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 2, generator1.getParameterKeys().size());
        final Iterator<String> i1 = generator1.getParameterKeys().iterator();
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, generator1.getParameterValue(i1.next()));
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, generator1.getParameterValue(i1.next()));
        // And
        final QueryCriteria qc2 = QueryCriteria.create().add(Criteria.and(Criteria.eq(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1), Criteria.eq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1)));
        QueryGenerator generator2 = QueryGenerator.generator(FakeEntity.class, qc2, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 = :field10 AND a.field2 = :field20", generator2.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 2, generator2.getParameterKeys().size());
        final Iterator<String> i2 = generator2.getParameterKeys().iterator();
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, generator2.getParameterValue(i2.next()));
        Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, generator2.getParameterValue(i2.next()));
    }

    @Test
    public void testBasicQueryOrder() {
        final QueryCriteria qc1 = QueryCriteria.create().add(Criteria.isNull(FakeEntity.FIELDNAME1)).add(Criteria.orderAsc(FakeEntity.FIELDNAME2));
        QueryGenerator generator1 = QueryGenerator.generator(FakeEntity.class, qc1, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 IS NULL ORDER BY a.field2 ASC", generator1.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, generator1.getParameterKeys().size());
        final QueryCriteria qc2 = QueryCriteria.create().add(Criteria.isNull(FakeEntity.FIELDNAME1)).add(Criteria.orderDesc(FakeEntity.FIELDNAME2));
        QueryGenerator generator2 = QueryGenerator.generator(FakeEntity.class, qc2, "a");
        Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 IS NULL ORDER BY a.field2 DESC", generator2.generate());
        Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, generator2.getParameterKeys().size());
    }

    @Test
    public void testAuditorQuery() {
        final Date timestamp = new Date();
        final String nodeId = "localhost";
        final QueryCriteria queryCriteria = QueryCriteria.create().add(Criteria.eq("nodeId", nodeId)).add(Criteria.leq("timeStamp", timestamp.getTime())).add(Criteria.orderAsc("sequenceNumber"));
        final QueryGenerator generator = QueryGenerator.generator(AuditRecordData.class, queryCriteria, "a");
        final String query = generator.generate();
        Assert.assertEquals("Wrong query generated", " WHERE a.nodeId = :nodeId0 AND a.timeStamp <= :timeStamp0 ORDER BY a.sequenceNumber ASC", query);
        // Make sure we get the same query if we generate again using the same criteria
        final QueryGenerator generator1 = QueryGenerator.generator(AuditRecordData.class, queryCriteria, "a");
        final String query1 = generator1.generate();
        Assert.assertEquals("Wrong query generated", " WHERE a.nodeId = :nodeId0 AND a.timeStamp <= :timeStamp0 ORDER BY a.sequenceNumber ASC", query1);
        
        final QueryCriteria queryCriteria2 = QueryCriteria.create().add(Criteria.leq("timeStamp", timestamp.getTime())).add(Criteria.orderAsc("sequenceNumber"));
        final QueryGenerator generator2 = QueryGenerator.generator(AuditRecordData.class, queryCriteria2, "a");
        final String query2 = generator2.generate();
        Assert.assertEquals("Wrong query generated", " WHERE a.timeStamp <= :timeStamp0 ORDER BY a.sequenceNumber ASC", query2);        
        // Make sure we get the same query if we generate again using the same criteria
        final QueryGenerator generator3 = QueryGenerator.generator(AuditRecordData.class, queryCriteria2, "a");
        final String query3 = generator3.generate();
        Assert.assertEquals("Wrong query generated", " WHERE a.timeStamp <= :timeStamp0 ORDER BY a.sequenceNumber ASC", query3);        
    }

    @Test
    public void testAttributeValidation() {
        try {
            QueryGenerator.generator(FakeEntity.class, QueryCriteria.create().add(Criteria.isNull("eventType IS NOT NULL or 1=1")), "a").generate();
            Assert.fail("attribute validation should throw exception");
        } catch (QueryParameterException e) {
            //Expected
        }
    }
}
