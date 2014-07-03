<%@ include file="header.jsp" %>

	<script type="text/javascript">
	    <!--
		myDeclare();
		// -->
	</script>

	<noscript>
		<div class="message">
		  <div class="label">Note</div>
		  <div class="content">
		    <p>Either JavaScript is turned off or your browser cannot
			handle JavaScript</p>
		  </div>
		</div>
	</noscript>

	<h1 class="title">Renewal of certificates on PrimeCard smart cards.</h1>

		<p>From this page you can renew the certificate on your smart card
		if you have NetID (4.2.0.18 or later) installed.</p>
		<p>The process is roughly like this:</p>

		<ol>
			<li>
				<p>This page is accessed with https and client authentication. The
				card that will have its certificates renewed should be used to
				authenticate with.</p>
			</li>
			<li>
				<p>The NetID plugin is used to create one certificate request for
				each key on the card with Javascript. These request are then posted
				to a servlet.</p>
			</li>
			<li>
				<p>The servlet checks if the client authentication certificate is
				revoked. If it is an error message is returned</p>
			</li>
			<li>
				<p>The servlet uses the client authentication certificate to find
				the user name.</p>
			</li>
			<li>
				<p>The status of the user is checked by the servlet. If not new an
				error message is returned.</p>
			</li>
			<li>
				<p>All unrevoked certificates belonging to the user are
				revoked (this should only be the old certificates of the card) by
				the servlet.</p>
			</li>
			<li>
				<p>New certificates for the card are issued by the servlet.</p>
			</li>
			<li>
				<p>A new response page is then created by the servlet. A template
				for this page is used. The page contains a Javascript that deletes
				the old revoked certificates and installs new ones instead. The
				template contains tags that are replaced by certificates to be
				removed or added.</p>
			</li>
		</ol>

		<p>Configuration of the servlet is made in the file
		<tt>./WEB-INF/web.xml</tt>. The class name of the servlet must be
		<tt>org.ejbca.ui.web.pub.CardCertReqServlet</tt>. 
		The following parameters are used:</p>

		<dl>
		  <dt>responseTemplate</dt>
		  <dd>The URL of the file to be used as response template.	Mandatory.</dd>
		  <dt>authCertProfile</dt>
		  <dd>Certificate profile used to create the new authenticating
			  certificate. If absent, the certificate profile of the user is
			  used.</dd>
		  <dt>signCertProfile</dt>
		  <dd>Certificate profile used to create the new signing certificate.
			  If absent, the certificate profile of the user is used.</dd>
		  <dt>signCA</dt>
		  <dd>CA used to sign the new signing certificate. If absent, the CA of
			  the user is used.</dd>
		  <dt>authCA</dt>
		  <dd>CA used to sign the new authenticating certificate. If absent,
			the CA of the user is used.</dd>
		</dl>

			<p>It is recommended that at least either <tt>authCertProfile</tt> or
			<tt>signCertProfile</tt> is used since key usage should be different 
			for the new certificates.</p>
			
			<form name="form1" action="cardcertreq" method="post" id="form1">
				<p>
				  <input type="hidden" name="hidemenu" value="<c:out value="${hidemenu}" />" >
				  <input type="HIDDEN" name="authpkcs10">
				  <input type="HIDDEN" name="signpkcs10">
				  <input type="BUTTON" value="Fetch Certificate" 
					style="width: 3.25cm; height: 0.66cm" onclick="generate_card_pkcs10()">
				</p>
			</form>
<%@ include file="footer.inc" %>
