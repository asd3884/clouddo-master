package com.bootdo.clouddoadmin.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import javax.sql.DataSource;

/**
 * @author bootdo
 * 配置授权服务器
 */
@Configuration
@EnableAuthorizationServer
public class Oauth2ServiceConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    DataSource dataSource;

    private Logger logger = LoggerFactory.getLogger(Oauth2ServiceConfig.class);

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        logger.info("授权开始---------------------");
        clients.inMemory()
                .withClient("app")//客户端id
                .scopes("read","write")//作用域
                .authorizedGrantTypes("authorization_code","password", "refresh_token")//授权码模式
                .redirectUris("http://localhost:8082/login") //跳转
                .secret(new BCryptPasswordEncoder().encode("123456"))//密匙
                .accessTokenValiditySeconds(10000) //token过期时间
                .refreshTokenValiditySeconds(100000); //refresh过期时间

        logger.info("===============配置授权服务器完成=========");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager);
        endpoints.tokenStore(jdbcTokenStore());
    }

    JdbcTokenStore jdbcTokenStore(){
        return new JdbcTokenStore(dataSource);
    }

//    @Bean
//    RedisTokenStore redisTokenStore(){
//        return new RedisTokenStore(connectionFactory);
//    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                // 开启/oauth/token_key验证端口无权限访问
                .tokenKeyAccess("permitAll()")
                // 开启/oauth/check_token验证端口认证权限访问  (资源访问的token解析端点)
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients();
    }


}
