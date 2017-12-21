/*
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package aljoin.cas;

import java.security.GeneralSecurityException;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.validation.constraints.NotNull;

import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

public class CustomQueryDatabaseAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {

	@NotNull
	private AljoinPasswordEncoder aljoinPasswordEncoder;
	
	@NotNull
	private String sql;

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected final HandlerResult authenticateUsernamePasswordInternal(final UsernamePasswordCredential credential)
			throws GeneralSecurityException, PreventedException {

		final String username = credential.getUsername();
		//final String encryptedPassword = this.getPasswordEncoder().encode(credential.getPassword());
		try {
			final String dbPassword = getJdbcTemplate().queryForObject(this.sql, String.class, username);
			/*if (!dbPassword.equals(encryptedPassword)) {
				throw new FailedLoginException("Password does not match value on record.");
			}*/
			if(!this.aljoinPasswordEncoder.matches(credential.getPassword(), dbPassword)){
				throw new FailedLoginException("Password does not match value on record.");
			}
		} catch (final IncorrectResultSizeDataAccessException e) {
			if (e.getActualSize() == 0) {
				throw new AccountNotFoundException(username + " not found with SQL query");
			} else {
				throw new FailedLoginException("Multiple records found for " + username);
			}
		} catch (final DataAccessException e) {
			throw new PreventedException("SQL exception while executing query for " + username, e);
		}
		return createHandlerResult(credential, this.principalFactory.createPrincipal(username), null);
	}

	public void setSql(final String sql) {
		this.sql = sql;
	}

	public void setAljoinPasswordEncoder(AljoinPasswordEncoder aljoinPasswordEncoder) {
		this.aljoinPasswordEncoder = aljoinPasswordEncoder;
	}

}
