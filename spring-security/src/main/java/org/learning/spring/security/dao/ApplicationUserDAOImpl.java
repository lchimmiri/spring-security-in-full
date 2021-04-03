package org.learning.spring.security.dao;

import java.util.List;
import java.util.Optional;

import org.learning.spring.security.auth.ApplicationUser;
import org.learning.spring.security.security.ApplicationUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

@Repository("fake")
public class ApplicationUserDAOImpl implements ApplicationUserDAO {

	private final PasswordEncoder passwordEncoder;

	@Autowired
	public ApplicationUserDAOImpl(PasswordEncoder passwordEncoder) {
		super();
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		// TODO Auto-generated method stub
		return getApplicationUsers().stream().filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}

	private List<ApplicationUser> getApplicationUsers() {
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
				new ApplicationUser("user", passwordEncoder.encode("user"),
						ApplicationUserRole.STUDENT.getGrantedAuthorities(), true, true, true, true),
				new ApplicationUser("admin", passwordEncoder.encode("admin"),
						ApplicationUserRole.STUDENT.getGrantedAuthorities(), true, true, true, true),
				new ApplicationUser("admint", passwordEncoder.encode("admin"),
						ApplicationUserRole.STUDENT.getGrantedAuthorities(), true, true, true, true));
		return applicationUsers;
	}
}
