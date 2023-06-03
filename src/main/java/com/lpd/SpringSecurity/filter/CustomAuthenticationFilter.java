package com.lpd.SpringSecurity.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

//import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/*
* Tìm hiểu thêm: unsuccessfulAuthentication cần tìm hiểu thêm về việc user đăng nhập sai quá số lần quy định sẽ bị khóa nick
* 1/@Slf4j để ghi log một số thông tin cần xem
* 2/Khi authenticate, với thông tin authentication trong class UsernamePasswordAuthenticationToken,
* Spring Security sẽ lấy thông tin username trong UsernamePasswordAuthenticationToken để kiểm tra trong UserCache đã có thông tin của username này chưa?
* */

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager; //Gọi authenticationManager để xác thực người dùng

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    //Nổ lực xác thực
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username"); //Lấy username từ tham số username của request
        String password = request.getParameter("password"); //Lấy password từ tham số password của request
        log.info("Username is: {}", username);
        log.info("Password is: {}", password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password); //Kiểm tra đã có thông tin username chưa
        return authenticationManager.authenticate(authenticationToken); //Xác thực
    }

    //Dùng để tạo (generate) và ký (sign) access token và refresh token gửi cho người dùng bất cứ khi nào người dùng đăng nhập thành công, hàm sẽ được gọi khi đăng nhập thành công
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        User user = (User)authentication.getPrincipal(); //User của Spring security, getPrincipal() nó sẽ trả về đối tượng User đã đăng nhập thành công.

        //Đã có quyền truy cập vào User vì người dùng đã đăng nhập. Lấy thông tin user để tạo JWT
        //Chuỗi secret là chuỗi để mã hóa của thuật toán
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); //Đối tượng Algorithm (thuật toán) từ library auth0, đây là thuậy toán sử dụng để ký (sign) JWT và refresh token.

        //Đưa thông tin và ký vào token để tạo access token
        //JWT.create() tạo access token
        //.withSubject() tiêu đề (đưa thông tin như ID hoặc username,...)
        //System.currentTimeMillis() là một method tĩnh của class System. Nó trả về khoảng thời gian bằng mili giây tính từ ngày 1-1-1970 cho tới thời điểm hiện tại của hệ thống bằng mili giây)
        //.withExpiresAt() hết hạn tại thời điểm (System.currentTimeMillis() + 10 * 60 * 1000 có nghĩa là token tồn tại 10 phút)
        //.withIssuer() đưa thông tin đường dẫn URL của request
        //.withClaim() tên là key của danh sách (roles là key) và các bộ sưu tập (Collection) đối tượng GrantedAuthority các role của user chuyển thành list rồi đưa vào
        //.sign() tạo chứ ký signature bằng thuật toán algorithm
        String access_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

        //Đưa thông tin và tạo refresh token
        //Đối với refresh token thì không cần đưa danh sách roles vào
        //Thời gian refresh token sẽ lâu hơn access token
        String refresh_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

        //Cách 1: Đưa access token và refresh token vào Header
        //Đưa access token và refresh token vào header
        //Bất cứ khi nào người dùng đăng nhập thành công, ta có thể check header của response, họ phải có access token và refresh token
//        response.setHeader("access_token", access_token);
//        response.setHeader("refresh_token", refresh_token);

        //Cách 2: Đưa access token và refresh token vào Body (tốt hơn)
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        //Cách 1:
        //response.setContentType(APPLICATION_JSON_VALUE); //APPLICATION_JSON_VALUE để chuột vào và chọn more actions "import static constant"
        //Cách 2:
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens); //Điều này sẽ trả ra các tokens trong Body
    }
}
