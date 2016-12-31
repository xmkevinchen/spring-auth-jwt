package com.ckai.samples.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author Kevin Chen
 *         CreatedAt: 12/30/16
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("fiona").password("password").roles("USER")
                .and()
                .withUser("kevin").password("password").roles("USER", "ADMIN");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                .anyRequest().authenticated()
            .and()
                .httpBasic().disable()
                .csrf().disable();
        // @formatter:on
    }
}
