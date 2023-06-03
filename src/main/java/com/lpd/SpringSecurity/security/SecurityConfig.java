package com.lpd.SpringSecurity.security;

import com.lpd.SpringSecurity.filter.CustomAuthenticationFilter;
import com.lpd.SpringSecurity.filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

/*
* 1/@Configuration để Spring chọn đây là file config
* 2/@EnableWebSecurity bật WebSecurity
* 3/WebSecurityConfigurerAdapter là một interface tiện ích của Spring Security giúp chúng ta cài đặt các thông tin dễ dàng hơn.
* 4/Method userDetailsService() có tác dụng cung cấp thông tin user cho Spring Security, chúng ta Override lại method này và cung cấp cho nó một User
* 5/Trong WebSecurityConfigurerAdapter chúng ta override lại method protected void configure(HttpSecurity http) để thực hiện việc phân quyền.
* 6/HttpSecurity là đối tượng chính của Spring Security, cho phép chúng ta cấu hình mọi thứ cần bảo mật,
* và nó được xây dựng dưới design pattern giống với Builder Pattern, nên mọi cài đặt có thể viết liên tục thông qua toán tử .
* 7/Những gì chúng ta muốn cho phép, chúng ta sẽ xài method .permit(), còn những gì cấm hoặc yêu cầu xác thực sẽ dùng .authenticated().
* 8/Khi gọi .formLogin() thì chúng ta cấu hình cho phép người dùng đăng nhập, thông qua địa chỉ mặc định /login do Spring Security
* tự tạo ra (Cái này có thể custom theo ý mình được).
* 9/.logout() cho phép người dùng logout, Nếu không nói gì thêm, Spring Security sẽ mặc định tự tạo ra một trang logout với địa chỉ /logout.
* 10/passwordEncoder() băm mật khẩu theo chuẩn mã hóa.
* 11/CSRF hay còn gọi là kỹ thuật tấn công “Cross-site Request Forgery“,
* nghĩa là kỹ thuật tấn công giả mạo chính chủ thể của nó.
* CSRF nói đến việc tấn công vào chứng thực request trên web thông qua việc sử dụng Cookies.
* Đây là nơi mà các hacker có khả năng sử dụng thủ thuật để tạo request mà bạn không hề biết.
* Vì vậy, một CSRF là hacker lạm dụng sự tin tưởng của một ứng dụng web trên trình duyệt của nạn nhân.
* 12/sessionManagement() quản lý phiên (session)
* 13/sessionCreationPolicy(SessionCreationPolicy.STATELESS) không tạo session
* 14/authorizeRequests() ủy quyền các request
* */

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //Chưa có 2 Bean UserDetailsService, BCryptPasswordEncoder cần phải tạo Bean để Spring chọn dùng
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    //Cấu hình quản lý xác thực, cách tìm kiếm user
    // (inMemoryAuthentication(): tìm user trong bộ nhớ in-memory,
    // jdbcAuthentication(): dùng JDBC để tìm kiếm user,
    // userDetailsService(): lấy user bằng username và trả về đối tượng UserDetails)
    // để xác thực (authentcation) và xác thực (verify)
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    //Ủy quyền các request và lọc xác thực người dùng đang cố đăng nhập
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");

        http.csrf().disable(); //Disable tấn công giả mạo CSRF
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //Không tạo session
        http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll(); //Đã custom lại url
        //http.authorizeRequests().antMatchers("/login").permitAll(); //"/login" là do CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter định nghĩa sẵn.
                                                                                //Có thể dùng luôn hoặc có thể custom lại url, thêm 2 dòng đầu vào, nếu ko thì ko cần thêm
        http.authorizeRequests().antMatchers(GET, "/api/user/**").hasAnyAuthority("ROLE_USER");
        http.authorizeRequests().antMatchers(POST, "/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");
        http.authorizeRequests().anyRequest().authenticated();
        //http.authorizeRequests().anyRequest().permitAll(); //Cho phép tất cả người dùng có quyền truy cập vào các yêu cầu.

        //Filter (bộ lọc xác thực để kiểm tra người dùng bất cứ khi nào họ cố gắng đăng nhập)
        //Đưa bộ lọc của chúng ta vào
        //http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));
        http.addFilter(customAuthenticationFilter);
        //Bộ lọc ủy quyền sẽ chặn và xử lý các request trước khi vào các bộ lọc khác
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    //Overide AuthenticationManager từ class WebSecurityConfigurerAdapter
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
