package org.learning.spring.security.dao;

import java.util.Optional;

import org.learning.spring.security.auth.ApplicationUser;

public interface ApplicationUserDAO {

	public Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
