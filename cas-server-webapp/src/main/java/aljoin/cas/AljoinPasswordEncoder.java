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

import org.jasig.cas.authentication.handler.PasswordEncoder;

/**
 * 
 * @描述：自定义密码加密器
 *
 * @作者：zhongjy
 *
 * @时间：2017年12月18日 下午7:45:26
 */
public class AljoinPasswordEncoder implements PasswordEncoder {
	
	private CustomPasswordEncoder customPasswordEncoder;
	
	

	@Override
	public String encode(String password) {
		return customPasswordEncoder.encode(password);
	}
	
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		return customPasswordEncoder.matches(rawPassword, encodedPassword);
	}

	public CustomPasswordEncoder getCustomPasswordEncoder() {
		return customPasswordEncoder;
	}

	public void setCustomPasswordEncoder(CustomPasswordEncoder customPasswordEncoder) {
		this.customPasswordEncoder = customPasswordEncoder;
	}

	
	
}
