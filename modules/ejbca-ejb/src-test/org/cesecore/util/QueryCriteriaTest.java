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

import java.util.Iterator;

import junit.framework.Assert;

import org.junit.Test;

/**
 * Verify that queries are generated dynamically as expected.
 * 
 * @version $Id$
 */
public class QueryCriteriaTest {

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
			QueryCriteria.where().eq(FakeEntity.FIELDNAME1, "value").conditions(FakeEntity.class);
		} catch (QueryParameterException e) {
			Assert.fail("QueryCriteria unable to detect existing field.");
		}
		try {
			QueryCriteria.where().eq("invalidParameterName", "value").conditions(FakeEntity.class);
			Assert.fail("QueryCriteria unable to detect non-existing field.");
		} catch (QueryParameterException e) {
			// Expected
		}
	}

	@Test
	public void testBasicQuery() {
		// This is the behavior.. perhaps it would be better to not return the "WHERE" clause when no parameters are present..
		final QueryCriteria qc = QueryCriteria.where();
		Assert.assertEquals(BAD_QUERY_GENERATED, "", qc.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, qc.getParameterKeys().size());
	}

	@Test
	public void testBasicQueryEqual() {
		final QueryCriteria qc1 = QueryCriteria.where().eq(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 = :field10", qc1.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, qc1.getParameterKeys().size());
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, qc1.getParameterValue(qc1.getParameterKeys().iterator().next()));
		final QueryCriteria qc2 = QueryCriteria.where().eq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 = :field20", qc2.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, qc2.getParameterKeys().size());
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, qc2.getParameterValue(qc2.getParameterKeys().iterator().next()));
	}

	@Test
	public void testBasicQueryGreaterOrEqual() {
		final QueryCriteria qc = QueryCriteria.where().geq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 >= :field20", qc.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, qc.getParameterKeys().size());
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, qc.getParameterValue(qc.getParameterKeys().iterator().next()));
	}

	@Test
	public void testBasicQueryLessOrEqual() {
		final QueryCriteria qc = QueryCriteria.where().leq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 <= :field20", qc.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, qc.getParameterKeys().size());
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, qc.getParameterValue(qc.getParameterKeys().iterator().next()));
	}

	@Test
	public void testBasicQueryBetween() {
		final QueryCriteria qc1 = QueryCriteria.where().between(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1, DUMMY_VALUE_STR2);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 BETWEEN :field10 AND :field11", qc1.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 2, qc1.getParameterKeys().size());
		final Iterator<String> i1 = qc1.getParameterKeys().iterator();
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, qc1.getParameterValue(i1.next()));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR2, qc1.getParameterValue(i1.next()));
		final QueryCriteria qc2 = QueryCriteria.where().between(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1, DUMMY_VALUE_INT2);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 BETWEEN :field20 AND :field21", qc2.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 2, qc2.getParameterKeys().size());
		final Iterator<String> i2 = qc2.getParameterKeys().iterator();
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, qc2.getParameterValue(i2.next()));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT2, qc2.getParameterValue(i2.next()));
	}

	@Test
	public void testBasicQueryLike() {
		final QueryCriteria qc = QueryCriteria.where().like(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 LIKE :field10", qc.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, qc.getParameterKeys().size());
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, qc.getParameterValue(qc.getParameterKeys().iterator().next()));
	}

	@Test
	public void testBasicQueryLess() {
		final QueryCriteria qc = QueryCriteria.where().lsr(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 < :field20", qc.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, qc.getParameterKeys().size());
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, qc.getParameterValue(qc.getParameterKeys().iterator().next()));
	}

	@Test
	public void testBasicQueryGreater() {
		final QueryCriteria qc = QueryCriteria.where().grt(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 > :field20", qc.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, qc.getParameterKeys().size());
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, qc.getParameterValue(qc.getParameterKeys().iterator().next()));
	}

	@Test
	public void testBasicQueryNotEqual() {
		final QueryCriteria qc1 = QueryCriteria.where();
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 != :field10", qc1.neq(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1).conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, qc1.getParameterKeys().size());
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, qc1.getParameterValue(qc1.getParameterKeys().iterator().next()));
		final QueryCriteria qc2 = QueryCriteria.where();
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 != :field20", qc2.neq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1).conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 1, qc2.getParameterKeys().size());
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, qc2.getParameterValue(qc2.getParameterKeys().iterator().next()));
	}

	@Test
	public void testBasicQueryNotNull() {
		final QueryCriteria qc1 = QueryCriteria.where().isNotNull(FakeEntity.FIELDNAME1);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 IS NOT NULL", qc1.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, qc1.getParameterKeys().size());
		final QueryCriteria qc2 = QueryCriteria.where().isNotNull(FakeEntity.FIELDNAME2);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 IS NOT NULL", qc2.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, qc2.getParameterKeys().size());
	}

	@Test
	public void testBasicQueryNull() {
		final QueryCriteria qc1 = QueryCriteria.where().isNull(FakeEntity.FIELDNAME1);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 IS NULL", qc1.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, qc1.getParameterKeys().size());
		final QueryCriteria qc2 = QueryCriteria.where().isNull(FakeEntity.FIELDNAME2);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field2 IS NULL", qc2.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, qc2.getParameterKeys().size());
	}

	@Test
	public void testCombinedQueryEqual() {
		// Or
		final QueryCriteria qc1 = QueryCriteria.where().eq(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1).or().eq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 = :field10 OR a.field2 = :field20", qc1.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 2, qc1.getParameterKeys().size());
		final Iterator<String> i1 = qc1.getParameterKeys().iterator();
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, qc1.getParameterValue(i1.next()));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, qc1.getParameterValue(i1.next()));
		// And
		final QueryCriteria qc2 = QueryCriteria.where().eq(FakeEntity.FIELDNAME1, DUMMY_VALUE_STR1).and().eq(FakeEntity.FIELDNAME2, DUMMY_VALUE_INT1);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 = :field10 AND a.field2 = :field20", qc2.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 2, qc2.getParameterKeys().size());
		final Iterator<String> i2 = qc2.getParameterKeys().iterator();
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_STR1, qc2.getParameterValue(i2.next()));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, DUMMY_VALUE_INT1, qc2.getParameterValue(i2.next()));
	}

	@Test
	public void testBasicQueryOrder() {
		final QueryCriteria qc1 = QueryCriteria.where().isNull(FakeEntity.FIELDNAME1).order(FakeEntity.FIELDNAME2, QueryCriteria.ORDER_ASC);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 IS NULL ORDER BY a.field2 ASC", qc1.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, qc1.getParameterKeys().size());
		final QueryCriteria qc2 = QueryCriteria.where().isNull(FakeEntity.FIELDNAME1).order(FakeEntity.FIELDNAME2, QueryCriteria.ORDER_DESC);
		Assert.assertEquals(BAD_QUERY_GENERATED, " WHERE a.field1 IS NULL ORDER BY a.field2 DESC", qc2.conditions(FakeEntity.class));
		Assert.assertEquals(BAD_QUERY_PARAMTERS, 0, qc2.getParameterKeys().size());
	}
}
