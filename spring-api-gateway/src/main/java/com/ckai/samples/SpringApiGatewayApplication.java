package com.ckai.samples;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringApiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringApiGatewayApplication.class, args);
    }

    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

        @Override
        public void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                    .antMatchers("/api/**").authenticated();

            // @formatter:on
        }

        @RestController
        @RequestMapping("/api")
        protected static class ResourceController {

            @RequestMapping(value = "/user", method = RequestMethod.GET)
            @PreAuthorize("hasRole('ROLE_USER')")
            public String helloUser() {
                return "hello user";
            }

            @RequestMapping(value = "/admin", method = RequestMethod.GET)
            @PreAuthorize("hasRole('ROLE_ADMIN')")
            public String helloAdmin() {
                return "hello admin";
            }
        }

    }

}



