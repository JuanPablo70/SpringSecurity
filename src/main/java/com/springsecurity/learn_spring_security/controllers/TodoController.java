package com.springsecurity.learn_spring_security.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.function.Predicate;

@RestController
public class TodoController {

    private Logger logger = LoggerFactory.getLogger(getClass());

    private static final List<Todo> TODOS_LIST =
            List.of(new Todo("User", "Learn Spring"),
            new Todo("User1", "Learn Spring Security"));

    @GetMapping("/todos")
    public List<Todo> getAllTodos() {
        return TODOS_LIST;
    }

    @GetMapping("/users/{username}/todos")
    public List<Todo> getTodosByUser(@PathVariable("username") String username) {
        Predicate<? super Todo> predicate = todo -> todo.username().equals(username);
        return TODOS_LIST.stream().filter(predicate).toList();
    }

    @PostMapping("/users/{username}/todos")
    public Todo createTodoByUser(@PathVariable("username") String username, @RequestBody Todo todo) {
        // CreateTodoLogic
        logger.info("Create {} for {}", todo, username);
        return todo;
    }

}

record Todo (String username, String description) {}
