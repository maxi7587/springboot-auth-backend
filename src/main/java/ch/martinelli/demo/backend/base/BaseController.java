package ch.martinelli.demo.backend.base;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/api")
public class BaseController {

    @GetMapping("")
    public void ok() {
    }

}
