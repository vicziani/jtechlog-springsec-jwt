package jtechlog.jwt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/api/hello")
    public HelloResponse sayHello() {
        return new HelloResponse("Hello JWT!");
    }
}
