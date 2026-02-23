package com.auth.demo.security;

import com.auth.demo.entity.User;
import com.auth.demo.repository.UserRepository;
import com.auth.demo.security.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String picture = oAuth2User.getAttribute("picture");
        String sub = oAuth2User.getAttribute("sub"); // Google's unique ID

        // Upsert user
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            user = User.builder()
                    .email(email)
                    .name(name)
                    .imageUrl(picture)
                    .provider(User.AuthProvider.GOOGLE)
                    .providerId(sub)
                    .build();
            userRepository.save(user);
        }

        String token = tokenProvider.generateToken(email);

        // Redirect to frontend with token in query param
        // Frontend reads it from URL and stores it
        //String redirectUrl = "http://localhost:5173/oauth2/callback?token=" + token;
        String redirectUrl = "https://nikilauth.netlify.app/oauth2/callback?token=" + token;
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}
