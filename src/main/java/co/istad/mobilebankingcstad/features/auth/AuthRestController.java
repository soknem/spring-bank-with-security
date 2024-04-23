package co.istad.mobilebankingcstad.features.auth;


import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/auth")
public class AuthRestController {

    @PostMapping("/login")
    public String login(){
        return "Login successfully ! ";
    }
    @PostMapping("/refresh-token")
    public String refreshToken(){
        return "Refresh token successfully ! ";
    }
    @PostMapping("/register")
    public String signUp(){
        return "Sign up successfully ! ";
    }
}
