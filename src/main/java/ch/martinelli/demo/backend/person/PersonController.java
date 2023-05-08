package ch.martinelli.demo.backend.person;

import ch.martinelli.demo.backend.auth.Roles;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

// The RolesAllowed annotation is used to restrict access to users with the role USER.
@RolesAllowed(Roles.USER)
@RestController
@RequestMapping("/api/persons") // Should be people!!!
public class PersonController {

    private final PersonService personService;

    public PersonController(PersonService personService) {
        this.personService = personService;
    }

    @GetMapping
    public List<Person> getAll() {
        return personService.findAll();
    }

    @GetMapping("/{id}")
    public Person getById(@PathVariable Integer id) {
        return personService.findById(id).orElseThrow();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public void post(@RequestBody Person person) {
        personService.save(person);
    }
}
