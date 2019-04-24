package com.freedom.auth.config;

import com.freedom.auth.security.JWTAuthenticationSuccessHandler;
import com.freedom.auth.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity  //开启Spring Security Web安全配置
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {  //重写WebSecurityConfigurerAdapter中的方法，用于自定义Spring Security配置

    @Autowired
    private UserDetailsService customUserDetailsService;

    /**
     * Authentication认证配置
     * 如果使用authenticationManagerBuilder.inMemoryAuthentication()会创建基于内存的DaoProviderManager认证
     * 但过程中创建的UserDetailService不会注入Spring容器
     * @Autowired UserDetailsService 使用的是UserDetailsServiceAutoConfiguration配置的默认账号密码
     *
     * @param authenticationManagerBuilder
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(customUserDetailsService)
                //.inMemoryAuthentication()
                //    .withUser("admin")
                //    .password(passwordEncoder().encode("123456"))
                //     //.password("$2a$10$5kzPGWrJd7FiMcbFQzEd9O56.EVsim5rrFzSRTEuGZT0MuDDYUjAi")
                //    .roles("USER_ROLE")
                //    .and()
                .passwordEncoder(passwordEncoder());  // 显示指定PasswordEncoder，此时设置的password需要是加密后的
                                                      // 因为不是通过UserDetail#build()出来的
                                                      // 且不能带{bcrypt}这种DelegatingPasswordEncoder采用的标示加密方法的id
    }


    /**
     * 配置认证信息也可以采用覆盖UserDetailsService的方式
     * 使用此种方法创建内存UserDetail时，无论是否使用withDefaultPasswordEncoder()
     * 都会使用默认的DelegatingPasswordEncoder，即将密码加密根据代理给其它Encoder
     * 如{bcrypt}开头代理给BCryptPasswordEncoder
     *   1、创建UserDetail时未指定PasswordEncoder，也没有withDefaultPasswordEncoder()，UserDetail#build()时，密码不变
     *      这种情况在验证用户名密码，执行到DelegatingPasswordEncoder#matches()时，无法通过{bcrypt}解析出加密方法id
     *      spring官方已经不建议在代码中出现明文的密码
     *   2、使用withDefaultPasswordEncoder()，即在创建UserDetail时就将其密码加密为{bcrypt}$2a$10$5kzPGWrJd7FiMcbFQzEd9O56.EVsim5rrFzSRTEuGZT0MuDDYUjAi
     *      这种情况可以正常认证登录，因为创建UserDetail和认证过程都用DelegatingPasswordEncoder
     * @return UserDetailsService
     */
    //@Bean
    //@Override
    //protected UserDetailsService userDetailsService() {
    //    // 1
    //    //UserDetails userDetails =
    //    //        User.withUsername("admin")
    //    //                .password("123456")
    //    //                .roles("USER_ROLE")
    //    //                .build();
    //
    //    // 2
    //    UserDetails userDetails =
    //            User.withDefaultPasswordEncoder()
    //                    .username("admin")
    //                    .password("123456")
    //                    .roles("USER_ROLE")
    //                    .build();
    //
    //    return new InMemoryUserDetailsManager(userDetails);
    //}

    /**
     * 密码编码器
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 解析JWT，还原Authentication的Filter
     * @return
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }


    // 认证成功处理器
    @Autowired
    private JWTAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;


    /**
     * 定义了哪些URL路径应该被拦截
     * 根路径 和 /home 都相当于首页，不需要权限
     * /hello需要登录后访问
     * @param httpSecurity
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  //服务器端无状态，即不是用session存储SecurityContext，RequestCatche等
                    .and()
                .authorizeRequests()  // 返回ExpressionInterceptUrlRegistry，可以注册基于URL的授权访问映射关系
                    .antMatchers("/", "/home").permitAll()  // 根路径和/home可直接访问
                    .anyRequest().authenticated()  // 其它URL需要认证后访问
                    .and()
                .formLogin()
                    .loginPage("/toLogin")  // toLogin作为登录入口
                    .loginProcessingUrl("/login")  // login作为处理登录请求URL
                    .permitAll()
                    .successHandler(jwtAuthenticationSuccessHandler)  // 认证成功处理器
                    .and()
                .logout()
                    .permitAll();

        // Add custom JWT security filter
        httpSecurity.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

}
