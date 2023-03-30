package com.springboot.admin.runner;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.springboot.admin.dto.CourseDTO;
import com.springboot.admin.dto.InstructorDTO;
import com.springboot.admin.dto.StudentDTO;
import com.springboot.admin.dto.UserDTO;
import com.springboot.admin.service.CourseService;
import com.springboot.admin.service.InstructorService;
import com.springboot.admin.service.RoleService;
import com.springboot.admin.service.StudentService;
import com.springboot.admin.service.UserService;

@Component
public class MyRunner implements CommandLineRunner{
	
	@Autowired
	private RoleService roleService;
	
	@Autowired
	private UserService userService;
	
	@Autowired
	private InstructorService instructorService;
	
	@Autowired
	private CourseService courseService;
	
	@Autowired
	private StudentService studentService;

	@Override
	public void run(String... args) throws Exception {
		
		createRoles();
		createAdmin();
		createInstructors();
		createCourses();
		StudentDTO student = createStudent();
		assignCourseToStudent(student);
		createStudents();
	}

	private void createStudents() {
		for(int i=1; i<10; i++) {
			StudentDTO studentDTO = new StudentDTO();
			studentDTO.setFirstName("studentFN"+i);
			studentDTO.setLastName("studentLN"+i);
			studentDTO.setLevel("intermediate"+i);
			UserDTO userDTO = new UserDTO();
			userDTO.setEmail("student"+i+"@gmail.com");
			userDTO.setPassword("1234");
			studentDTO.setUser(userDTO);
			studentService.createStudent(studentDTO);
		}
	}

	private void createRoles() {
		Arrays.asList("Admin", "Instructor", "Student").forEach(role ->roleService.createRole(role));
	}

	private void createAdmin() {
		userService.createUser("admin@gmail.com", "1234");
		userService.assignRoleToUser("admin@gmail.com", "Admin");
	}

	private void createInstructors() {
		for(int i=0; i<10; i++) {
			InstructorDTO instructorDTO = new InstructorDTO();
			instructorDTO.setFirstName("instructor"+i+"FN");
			instructorDTO.setLastName("instructor"+i+"LN");
			instructorDTO.setSummary("master"+i);
			UserDTO userDTO = new UserDTO();
			userDTO.setEmail("instructor"+i+"@gmail.com");
			userDTO.setPassword("1234");
			instructorDTO.setUser(userDTO);
			instructorService.createInstructor(instructorDTO);
		}
	}

	private void createCourses() {
		for(int i=0; i<10; i++) {
			CourseDTO courseDTO = new CourseDTO();
			courseDTO.setCourseDescription("java"+i);
			courseDTO.setCourseDuration(i+"hours");
			courseDTO.setCourseName("java course"+i);
			InstructorDTO instructorDTO = new InstructorDTO();
			instructorDTO.setInstructorId(1L);
			courseDTO.setInstructor(instructorDTO);
			courseService.createCourse(courseDTO);
		}
	}

	private StudentDTO createStudent() {
		StudentDTO studentDTO = new StudentDTO();
		studentDTO.setFirstName("studentFN");
		studentDTO.setLastName("studentLN");
		studentDTO.setLevel("intermediate");
		UserDTO userDTO = new UserDTO();
		userDTO.setEmail("student@gmail.com");
		userDTO.setPassword("1234");
		studentDTO.setUser(userDTO);
		return studentService.createStudent(studentDTO);
	}

	private void assignCourseToStudent(StudentDTO student) {
		courseService.assignStudentToCourse(1L, student.getStudentId());
	}

	
}
