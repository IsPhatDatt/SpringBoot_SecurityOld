package com.lpd.SpringSecurity.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;

/*
* 1/Chuỗi getServletPath(): Trả về một phần của URL của request này gọi là JSP.
* */

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    //Để lọc các request đến, xem User có quyền truy cập vào ứng dụng hoặc không, nó sẽ chặn mọi request đến ứng dụng.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //Nếu URL của request là "/api/login" thì không cần xử lý request hay bất kì điều gì vì nó là permitAll (ai cũng có quyền vào)
        //Ngược lại là URL khác thì ...
        if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) {
            filterChain.doFilter(request, response);
        } else {
            //Chuỗi token JWT phải được thêm vào Authorization Header ở mỗi HTTP Request nếu Client truy cập vào tài nguyên được bảo vệ.
            //Trong trường hợp Token hết hạn Client sẽ cần Refresh Token
            //AUTHORIZATION là key trong Header
            String authorizationHeader = request.getHeader(AUTHORIZATION); //authorizationHeader là "Bearer token"
            //Nếu Client gửi request có authorization header khác null và bắt đầu bằng "Bearer "
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                try {
                    //Cắt bỏ chuỗi "Bearer " để lấy token
                    String token = authorizationHeader.substring("Bearer ".length());
                    //Tạo đúng đối tượng thuật toán khi mã hóa password bên class CustomAuthenticationFilter
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                    //Tạo người xác minh (Verifier) cùng với thuật toán và khóa của thuật toán, phải build() để trả về đối tượng JWTVerifier
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    //Giải mã (decode), dùng người xác minh (JWTVerifier) để giải mã token
                    DecodedJWT decodedJWT = verifier.verify(token);
                    //Lấy username từ token đã giải mã, username được đặt trong subject khi Application tạo ra token đó.
                    String username = decodedJWT.getSubject();
                    //Lấy role của user bằng getClaim("ten key list lúc tạo token") từ list roles và chuyển list roles thành mảng String
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    //Tạo ra bộ sưu tập các role của user
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    //Thêm role vào bộ sưu tập
                    stream(roles).forEach(role -> {
                        authorities.add(new SimpleGrantedAuthority(role));
                    });
                    //Kiểm tra đã có thông tin username và quyền chưa, không cần password
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);
                    //(SecurityContextHolder.getContext()).getAuthentication().getPrincipal(): đây chính là method giúp lấy thông tin User trong Spring Security
                    //Set chuỗi authenticationToken đó cho UserPrincipal (user đang đăng nhập)
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    //Gọi chuỗi (dây chuyền) bộ lọc
                    filterChain.doFilter(request, response);
                } catch (Exception exception) {
                    //Bắt tất cả các ngoại lệ, giả sử là token không hợp lệ
                    log.error("Error logging in: {}", exception.getMessage());
                    response.setHeader("error", exception.getMessage()); //Set tiêu đề báo lỗi
                    response.setStatus(FORBIDDEN.value());
                    //response.sendError(FORBIDDEN.value()); //Gửi mã lỗi 403 là không có quyền
                    Map<String, String> error = new HashMap<>();
                    error.put("error_message", exception.getMessage());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
