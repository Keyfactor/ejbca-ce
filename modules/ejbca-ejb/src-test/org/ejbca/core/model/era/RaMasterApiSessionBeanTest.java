package org.ejbca.core.model.era;

import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.easymock.Capture;
import org.easymock.CaptureType;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RaMasterApiSessionBeanTest {
    private EntityManager entityManager;
    private Capture<String> queryString;
    private Capture<String> parameters;

    @Test
    public void testStringSearchQueryClause() throws Exception {
        RaCertificateSearchRequestV2 raRequest = new RaCertificateSearchRequestV2();

        // no values is empty string
        assertEquals("", RaMasterApiSessionBean.buildStringSearchClause(raRequest));
        
        // one value is a simple and clause
        raRequest.setSubjectDnSearchString("value");
        assertEquals(" AND (UPPER(subjectDN) LIKE :subjectDN)", 
                RaMasterApiSessionBean.buildStringSearchClause(raRequest));
        
        // more than one value is and (x OR y)
        raRequest.setSubjectAnSearchString("value");
        assertEquals(" AND (UPPER(subjectDN) LIKE :subjectDN OR subjectAltName LIKE :subjectAltName)", 
                RaMasterApiSessionBean.buildStringSearchClause(raRequest));
        
        // search critera BEGINS_WITH is case sensitive
        raRequest.setSubjectDnSearchOperation("BEGINS_WITH");
        assertEquals(" AND (subjectDN LIKE :subjectDN OR subjectAltName LIKE :subjectAltName)", 
        RaMasterApiSessionBean.buildStringSearchClause(raRequest));
    }
    
    @Before
    public void setupEntityManagerMock() {
        parameters = EasyMock.newCapture(CaptureType.ALL);
        Query query = EasyMock.createNiceMock(Query.class);
        EasyMock.expect(query.setParameter(EasyMock.capture(parameters), EasyMock.anyObject())).andReturn(query).anyTimes();
        
        entityManager = EasyMock.createNiceMock(EntityManager.class);
        queryString = EasyMock.newCapture();
        EasyMock.expect(entityManager.createNativeQuery(EasyMock.capture(queryString))).andReturn(query);
        replay(query);
        replay(entityManager);  
    }
    
    @Test
    public void testCreateQuery() throws Exception {
        RaCertificateSearchRequestV2 request = new RaCertificateSearchRequestV2();
        request.setSubjectAnSearchString("XYZ");
        request.setSubjectDnSearchString("ABC");
        RaMasterApiSessionBean.createQuery(entityManager, request, false, null, null, false, null, false);
        
        assertTrue(queryString.getValue().contains("AND (UPPER(subjectDN) LIKE :subjectDN OR subjectAltName LIKE :subjectAltName)"));
        assertTrue(parameters.getValues().contains("subjectDN"));
        assertTrue(parameters.getValues().contains("subjectAltName"));
        
        assertFalse(parameters.getValues().contains("serialNumber"));
    }
}
