package com.lpd.SpringSecurity;

import com.lpd.SpringSecurity.domain.Role;
import com.lpd.SpringSecurity.domain.User;
import com.lpd.SpringSecurity.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	} //Tạo Bean passwordEncoder để Spring chọn dùng

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			userService.saveUser(new User(null, "Phat Dat", "dat", "1", new ArrayList<>()));
			userService.saveUser(new User(null, "Phat Dat", "dat1", "1", new ArrayList<>()));
			userService.saveUser(new User(null, "Phat Dat", "dat2", "1", new ArrayList<>()));
			userService.saveUser(new User(null, "Phat Dat", "dat3", "1", new ArrayList<>()));

			userService.addRoleToUser("dat", "ROLE_USER");
			userService.addRoleToUser("dat", "ROLE_MANAGER");
			userService.addRoleToUser("dat1", "ROLE_MANAGER");
			userService.addRoleToUser("dat2", "ROLE_ADMIN");
			userService.addRoleToUser("dat3", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("dat3", "ROLE_USER");
			userService.addRoleToUser("dat3", "ROLE_MANAGER");


		}; //Những thứ trong {} này sẽ chạy sau khi ứng dựng được khởi tạo
	}

}
