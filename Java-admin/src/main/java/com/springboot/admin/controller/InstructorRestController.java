package com.springboot.admin.controller;

import java.util.List;

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
import com.springboot.admin.dto.InstructorDTO;
import com.springboot.admin.entity.User;
import com.springboot.admin.service.CourseService;
import com.springboot.admin.service.InstructorService;
import com.springboot.admin.service.UserService;

@RestController
@RequestMapping("/instructors")
@CrossOrigin("*")
public class InstructorRestController {

	private InstructorService instructorService;
	private UserService userService;
	private CourseService courseService;

	public InstructorRestController(InstructorService instructorService, UserService userService,
			CourseService courseService) {
		super();
		this.instructorService = instructorService;
		this.userService = userService;
		this.courseService = courseService;
	}

	@GetMapping
	@PreAuthorize("hasAuthority('Admin')")
	public Page<InstructorDTO> searchInstructors(@RequestParam(name="keyword", defaultValue = "")String keyword,
												 @RequestParam(name="page", defaultValue = "0")int page,
												 @RequestParam(name="size", defaultValue = "5")int size){
		return instructorService.findInstructorsByName(keyword, page, size);
	}
	
	@GetMapping("/all")
	@PreAuthorize("hasAuthority('Admin')")
	public List<InstructorDTO> findAllInstructors(){
		return instructorService.fetchInstructors();
	}
	
	@DeleteMapping("/{instructorId}")
	@PreAuthorize("hasAuthority('Admin')")
	public void deleteInstructor(@PathVariable Long instructorId) {
		instructorService.removeInstructor(instructorId);
	}
	
	@PostMapping
	@PreAuthorize("hasAuthority('Admin')")
	public InstructorDTO saveInstructor(@RequestBody InstructorDTO instructorDTO) {
		User user = userService.loadUserByEmail(instructorDTO.getUser().getEmail());
		if(user != null) throw new RuntimeException("Email already exist");
		return instructorService.createInstructor(instructorDTO);
	}
	
	@PutMapping("/{instructorId}")
	@PreAuthorize("hasAuthority('Instructor')")
	public InstructorDTO updateInstructor(@RequestBody InstructorDTO instructorDTO, @PathVariable Long instructorId) {
		instructorDTO.setInstructorId(instructorId);
		return instructorService.updateInstructor(instructorDTO);
	}
	
	@GetMapping("/{instructorId}/courses")
	@PreAuthorize("hasAnyAuthority('Admin','Instructor')")
	public Page<CourseDTO> coursesByInstructorId(@PathVariable Long instructorId,
												 @RequestParam (name="page", defaultValue = "0")int page,
												 @RequestParam (name="size", defaultValue = "5")int size){
		return courseService.fetchCoursesForInstructor(instructorId, page, size);
	}
	
	@GetMapping("/find")
	@PreAuthorize("hasAuthority('Instructor')")
	public InstructorDTO loadInstructorByEmail(@RequestParam(name="email", defaultValue = "")String email) {
		return instructorService.loadInstructorByEmail(email);
	}
}
