/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.util;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Simple class for mocking an interface that can return pre-configured values
 * or throw defined Exceptions.<br/>
 * <br/>
 * The mocked object will treat two methods with the same name, but different
 * signatures as the same. (E.g. getInt() and getInt(String x) will be treated
 * the same.)<br/>
 * <br/>
 * Example usage:<br/>
 * <pre>
 *  SomeInterface x = new SimpleMock(SomeInterface.class) {{
 *  	map("getInt", 1); // Override method getInt(...)
 *  	map("throwsException", new Exception("TestException")); // Override method throwsException(...)
 *  }}.mock();
 *  x.getInt("parameter 1", 2, "parameter 3");	// Will return 1
 *  </pre>
 *
 *  Unmapped methods will return the following defaults:
 *  <ul>
 *   <li>boolean: false</li>
 *   <li>char: '\0'</li>
 *   <li>byte: 0</li>
 *   <li>short: 0</li>
 *   <li>int: 0</li>
 *   <li>long: 0</li>
 *   <li>float: 0.0</li>
 *   <li>double: 0.0</li>
 *   <li>Object: null</li>
 *  </ul>
 *  
 *  @version $Id$
 */
public class SimpleMock {
	
	final Class<?> c;
	final Map<String, Object> map = new HashMap<String, Object>();
	final List<String> methodNames = new ArrayList<String>();

	/** @param c is the interface to mock */
	public SimpleMock(Class<?> c) {
		if (!c.isInterface()) {
			throw new RuntimeException(c.getName() + " is not an interface.");
		}
		this.c = c;
		Class<?> thisInterface = c;
		while (thisInterface != null) {
			for (Method m : c.getMethods()) {
				methodNames.add(m.getName());
			}
			thisInterface = c.getSuperclass();
		}
	}
	
	/**
	 * Adds a mapping between a method-name and return value
	 * @param methodName
	 * @param valueOrException
	 */
	public void map(String methodName, Object valueOrException) {
		if (!methodNames.contains(methodName)) {
			throw new RuntimeException(new NoSuchMethodException(methodName));
		}
		map.put(methodName, valueOrException);
	}
	
	@SuppressWarnings("unchecked")
	public <T> T mock() {
		Class<?>[] cs = {c};
		return (T) Proxy.newProxyInstance(c.getClassLoader(), cs, new MockInvocationHandler(map));
	}

	/**
	 * Injects "value" into a (private) field named "fieldName" of "target" or
	 * the first one of "target"'s super classes where "fieldName" exists.
	 */
    public static void inject(Object target, String fieldName, Object value) {
		try {
			Field field = null;
			Class<?> targetClass = target.getClass();
			while (targetClass != null) {
				try {
					field = targetClass.getDeclaredField(fieldName);
					break;
				} catch (NoSuchFieldException e) {
				}
				targetClass = targetClass.getSuperclass();
			}
			if (targetClass == null) {
				throw new NoSuchFieldException(fieldName);
			}
	        field.setAccessible(true);
	        field.set(target, value);
		} catch (SecurityException e) {
			throw new RuntimeException(e);
		} catch (NoSuchFieldException e) {
			throw new RuntimeException(e);
		} catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
    }

	private class MockInvocationHandler implements InvocationHandler {

		final Map<String, Object> map;
		
		public MockInvocationHandler(Map<String, Object> map) {
			this.map = map;
		}
		
		@Override
		public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
			// Check if we should return a mapped value
			final String methodName = method.getName();
			if (map.containsKey(methodName)) {
				final Object returnValue = map.get(methodName);
				if (returnValue instanceof Throwable) {
					throw (Throwable)returnValue;
				} else {
					return returnValue;
				}
			}
			// No mapped value was configured, so return the default for this return type
			final Class<?> returnType = method.getReturnType();
			if (returnType.isPrimitive()) {
				// We cannot return null if it is a primitive type.
				final String returnTypeName = returnType.getName();
				if ("boolean".equals(returnTypeName)) {
					return false;
				} else if ("char".equals(returnTypeName)) {
					return '\0';
				} else if ("byte".equals(returnTypeName)) {
					return (byte)0;
				} else if ("short".equals(returnTypeName)) {
					return (short)0;
				} else if ("int".equals(returnTypeName)) {
					return (int)0;
				} else if ("long".equals(returnTypeName)) {
					return (long)0L;
				} else if ("float".equals(returnTypeName)) {
					return (float)0.0F;
				} else if ("double".equals(returnTypeName)) {
					return (double)0.0D;
				}
			}
			return null;
		}
	}
}
