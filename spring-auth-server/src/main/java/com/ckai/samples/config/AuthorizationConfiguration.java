package com.ckai.samples.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author Kevin Chen
 *         CreatedAt: 12/30/16
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationConfiguration extends AuthorizationServerConfigurerAdapter {

    private final static Logger logger = LoggerFactory.getLogger(AuthorizationConfiguration.class);

    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthorizationConfiguration(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // @formatter:off
        endpoints
            .authenticationManager(authenticationManager)
            .tokenStore(tokenStore())
            .accessTokenConverter(jwtAccessTokenConverter());
        // @formatter:on
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // @formatter:off
        clients.inMemory()
            .withClient("app")
            .secret("app-secret")
            .authorizedGrantTypes("password")
            .authorities("ROLE_CLIENT")
            .scopes("openid");
        // @formatter:on
    }

    @Value("${config.jwt.privateKey}")
    private String privateKey;

    @Value("${config.jwt.publicKey}")
    private String publicKey;

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(privateKey);
        converter.setVerifierKey(publicKey);

        return converter;
    }

    @Bean
    public JwtTokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }


    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // @formatter:off
        security
            .tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_CLIENT')")
            .checkTokenAccess("hasAuthority('ROLE_CLIENT')");
        // @formatter:on
    }
}

@RestController
class PrincipleRestController {

    @RequestMapping(method = RequestMethod.GET, value = "/user")
    public Principal principal(Principal principal) {
        return principal;
    }
}
