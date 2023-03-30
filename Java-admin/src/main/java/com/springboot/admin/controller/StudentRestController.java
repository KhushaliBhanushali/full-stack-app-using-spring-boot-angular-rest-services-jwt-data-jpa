package com.springboot.admin.controller;

import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.admin.dto.CourseDTO;
import com.springboot.admin.dto.StudentDTO;
import com.springboot.admin.entity.User;
import com.springboot.admin.service.CourseService;
import com.springboot.admin.service.StudentService;
import com.springboot.admin.service.UserService;

@RestController
@RequestMapping("/students")
@CrossOrigin("*")
public class StudentRestController {

	private StudentService studentService;
	private UserService userService;
	private CourseService courseService;

	public StudentRestController(StudentService studentService, UserService userService, CourseService courseService) {
		super();
		this.studentService = studentService;
		this.userService = userService;
		this.courseService = courseService;
	}

	@GetMapping
	@PreAuthorize("hasAuthority('Admin')")
	public Page<StudentDTO> searchStudent(@RequestParam(name="keyword", defaultValue = "")String keyword,
										  @RequestParam(name="page", defaultValue = "0")int page,
										  @RequestParam(name="size", defaultValue = "5")int size){
		return studentService.loadStudentsByName(keyword, page, size);
	}
	
	@DeleteMapping("/{studentId}")
	@PreAuthorize("hasAuthority('Admin')")
	public void deleteStudent(@PathVariable Long studentId) {
		studentService.removeStudent(studentId);
	}
	
	@PostMapping
	@PreAuthorize("hasAuthority('Admin')")
	public StudentDTO saveStudent(@RequestBody StudentDTO studentDTO) {
		User user = userService.loadUserByEmail(studentDTO.getUser().getEmail());
		if(user != null) throw new RuntimeException("Email Already Exist");
		return studentService.createStudent(studentDTO);
	}
	
	@PutMapping("/{studentId}")
	@PreAuthorize("hasAuthority('Student')")
	public StudentDTO updateStudent(@RequestBody StudentDTO studentDTO, @PathVariable Long studentId) {
		studentDTO.setStudentId(studentId);
		return studentService.updateStudent(studentDTO);
	}
	
	@GetMapping("/{studentId}/courses")
	@PreAuthorize("hasAuthority('Student')")
	public Page<CourseDTO> coursesByStudentId(@PathVariable Long studentId,
											  @RequestParam(name="page", defaultValue = "0")int page,
											  @RequestParam(name="size", defaultValue = "5")int size){
		return courseService.fetchCoursesForStudent(studentId, page, size);
	}
	
	@GetMapping("/{studentId}/other-courses")
	@PreAuthorize("hasAuthority('Student')")
	public Page<CourseDTO> nonSubscribedCoursesByStudentId(@PathVariable Long studentId,
											  @RequestParam(name="page", defaultValue = "0")int page,
											  @RequestParam(name="size", defaultValue = "5")int size){
		return courseService.fetchNonEnrolledInCoursesForStudent(studentId, page, size);
	}
	
	@GetMapping("/find")
	@PreAuthorize("hasAuthority('Student')")
	public StudentDTO loadStudentByEmail(@RequestParam(name="email", defaultValue = "")String email) {
		return studentService.loadStudentByEmail(email);
	}
}

