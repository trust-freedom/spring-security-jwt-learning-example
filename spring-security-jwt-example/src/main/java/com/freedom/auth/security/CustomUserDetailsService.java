package com.freedom.auth.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * 自定义内存型UserDetailsService
 * 如果使用authenticationManagerBuilder.inMemoryAuthentication()会导致过滤器链使用配置的内存认证，但没有交给Spring容器管理
 * 而@Autowired UserDetailsService 使用的是UserDetailsServiceAutoConfiguration配置的默认账号密码
 */
//@Service
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 基于内存的数据，目前只有admin用户
        if("admin".equals(username)){
            User user = new User(username, passwordEncoder.encode("123456"), AuthorityUtils.commaSeparatedStringToAuthorityList("USER_ROLE"));
            log.info("认证成功");
            return user;
        }

        log.info("认证失败");
        return null;
    }
}
