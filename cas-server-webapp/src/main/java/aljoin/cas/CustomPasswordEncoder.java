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

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 
 * @描述：自定义密码加密器
 *
 * @作者：zhongjy
 *
 * @时间：2017年5月4日 下午12:27:37
 */
public class CustomPasswordEncoder extends BCryptPasswordEncoder {

	/**
	 * 加密强度设置为10(强度越高，时间越长)
	 */
	public CustomPasswordEncoder() {
		super(10);
	}

	/**
	 * 加密
	 */
	public String encode(CharSequence rawPassword) {
		return super.encode(rawPassword);
	}

	/**
	 * 校验 rawPassword-原密码(明文) encodedPassword-密文(数据库取出的加密密码)
	 */
	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		return super.matches(rawPassword, encodedPassword);
	}

}
