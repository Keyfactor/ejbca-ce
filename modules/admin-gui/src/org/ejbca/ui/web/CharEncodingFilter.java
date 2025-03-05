package org.ejbca.ui.web;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;

import java.io.IOException;

@WebFilter("/*")
public class CharEncodingFilter implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws ServletException, IOException {
		request.setCharacterEncoding("UTF-8");
		chain.doFilter(request, response);
	}
}
