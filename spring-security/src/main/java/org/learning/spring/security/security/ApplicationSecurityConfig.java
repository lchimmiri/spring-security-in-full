package org.learning.spring.security.security;

import static org.learning.spring.security.security.ApplicationUserRole.ADMIN;
import static org.learning.spring.security.security.ApplicationUserRole.ADMINTRAINEE;
import static org.learning.spring.security.security.ApplicationUserRole.STUDENT;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

	private PasswordEncoder passwordEncoder;

	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
				// .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
				.authorizeRequests()
				.antMatchers("/", "index", "/css/", "/js/*")
				.permitAll()
				.antMatchers("/api/**")
				.hasRole(ApplicationUserRole.STUDENT.name())
				.anyRequest()
				.authenticated()
				.and()
				.formLogin()
				.loginPage("/login").permitAll().defaultSuccessUrl("/courses", true)
				.and()
				.rememberMe()
				.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
				.key("somethingreallysecuredhere")
				.and()
				.logout()
				.logoutUrl("/logout")
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID", "remember-me")
				.logoutSuccessUrl("/login"); // defaults to 2 weeks
	}

	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails student = User.builder().username("user").password(passwordEncoder.encode("user"))
//				.roles(STUDENT.name())
				.authorities(STUDENT.getGrantedAuthorities()).build();

		UserDetails admin = User.builder().username("admin").password(passwordEncoder.encode("admin"))
//				.roles(ADMIN.name())
				.authorities(ADMIN.getGrantedAuthorities()).build();

		UserDetails adminTrainee = User.builder().username("admint").password(passwordEncoder.encode("admin"))
//				.roles(ADMINTRAINEE.name())
				.authorities(ADMINTRAINEE.getGrantedAuthorities()).build();

		return new InMemoryUserDetailsManager(student, admin, adminTrainee);
	}
}
