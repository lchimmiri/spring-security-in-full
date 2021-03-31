package org.learning.spring.security.controller;

import java.util.Arrays;
import java.util.List;

import org.learning.spring.security.entity.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController {
	private static final List<Student> STUDENTS = Arrays.asList(new Student(1, "Naidu"), new Student(2, "Sahasra"),
			new Student(3, "Bulli"));

	// hasRole("ROLE_") hasAnyRole("ROLE_") hasAuthority("permission")
	// hasAnyAuthority("permission")
	@GetMapping("/")
	@PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
	public List<Student> getAllStudents() {
		System.out.println("GET : getAllStudents");
		return STUDENTS;
	}

	@PostMapping("/")
	@PreAuthorize("hasAuthority('student:write')")
	public void registerNewStudent(@RequestBody Student student) {
		System.out.println("POST : registerNewStudent");
		System.out.println(student);
	}

	@DeleteMapping("/{studentId}")
	@PreAuthorize("hasAuthority('student:write')")
	public void deleteStudent(@PathVariable("studentId") Integer studentId) {
		System.out.println("DELETE : deleteStudent");
		System.out.println(studentId);
	}

	@PutMapping("/{studentId}")
	@PreAuthorize("hasAuthority('student:write')")
	public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
		System.out.println("PUT : updateStudent");
		System.out.println(String.format("%s %s", studentId, student));
	}

}
