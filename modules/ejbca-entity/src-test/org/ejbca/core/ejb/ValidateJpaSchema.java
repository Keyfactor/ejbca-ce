package org.ejbca.core.ejb;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

/**
 * Simple class to trigger Hibernate's JPA schema validation.
 * 
 * @version $Id$
 */
public class ValidateJpaSchema {
	
	public static void main(String[] args) throws Exception {
		EntityManagerFactory entityManagerFactory1 = Persistence.createEntityManagerFactory("ejbca-pu");
		EntityManager entityManager = entityManagerFactory1.createEntityManager();
		try {
			//EntityTransaction transaction = entityManager.getTransaction();
			//transaction.begin();
			//transaction.commit();
			
		} finally {
			entityManager.close();
			entityManagerFactory1.close();
		}
	}


}
