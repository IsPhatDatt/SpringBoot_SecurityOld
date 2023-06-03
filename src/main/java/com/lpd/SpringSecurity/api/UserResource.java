package com.lpd.SpringSecurity.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lpd.SpringSecurity.domain.Role;
import com.lpd.SpringSecurity.domain.User;
import com.lpd.SpringSecurity.service.UserService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;

//Inject the service, not controller
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserResource {
    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers() {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/user/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    //Xác thực refresh token. Khi access token hết hạn thì gọi API này để cấp lại access token mới
    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                //Cắt bỏ chuỗi "Bearer " để lấy refresh_token
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                //Tạo đúng đối tượng thuật toán khi mã hóa password bên class CustomAuthenticationFilter
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                //Tạo người xác minh (Verifier) cùng với thuật toán và khóa của thuật toán, phải build() để trả về đối tượng JWTVerifier
                JWTVerifier verifier = JWT.require(algorithm).build();
                //Giải mã (decode), dùng người xác minh (JWTVerifier) để giải mã refresh_token
                DecodedJWT decodedJWT = verifier.verify(refresh_token);
                //Lấy username từ refresh_token đã giải mã, username được đặt trong subject khi Application tạo ra refresh_token đó.
                String username = decodedJWT.getSubject();
                //Lấy thông tin user của Application bằng cách getUser() với username lấy được khi giải mã refresh_token
                User user = userService.getUser(username);
                //
                String access_token = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens); //Điều này sẽ trả ra các tokens trong Body
            } catch (Exception exception) {
                response.setHeader("error", exception.getMessage()); //Set tiêu đề báo lỗi
                response.setStatus(FORBIDDEN.value());
                //response.sendError(FORBIDDEN.value()); //Gửi mã lỗi 403 là không có quyền
                Map<String, String> error = new HashMap<>();
                error.put("error_message", exception.getMessage());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }
}

@Data
class RoleToUserForm {
    private String username;
    private String roleName;
}
