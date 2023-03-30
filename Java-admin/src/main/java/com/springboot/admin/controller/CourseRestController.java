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
import com.springboot.admin.service.CourseService;

@RestController
@RequestMapping("/courses")
@CrossOrigin("*")
public class CourseRestController {

	private CourseService courseService;

	public CourseRestController(CourseService courseService) {
		super();
		this.courseService = courseService;
	}
	
	@GetMapping
	@PreAuthorize("hasAuthority('Admin')")
	public Page<CourseDTO> searchCourses(@RequestParam(name="keyword",defaultValue = "")String keyword,
										 @RequestParam(name="page",defaultValue = "0")int page,
										 @RequestParam(name="size",defaultValue = "5")int size){
		return courseService.findCoursesByCourseName(keyword, page, size);
	}
	
	@DeleteMapping("/{courseId}")
	@PreAuthorize("hasAuthority('Admin')")
	public void deleteCourse(@PathVariable Long courseId) {
		courseService.removeCourse(courseId);
	}
	
	@PostMapping
	@PreAuthorize("hasAnyAuthority('Admin','Instructor')")
	public CourseDTO saveCourse(@RequestBody CourseDTO courseDTO) {
		return courseService.createCourse(courseDTO);
	}
	
	@PutMapping("/{courseId}")
	@PreAuthorize("hasAnyAuthority('Admin','Instructor')")
	public CourseDTO updateCourse(@RequestBody CourseDTO courseDTO, @PathVariable Long courseId) {
		courseDTO.setCourseId(courseId);
		return courseService.updateCourse(courseDTO);
	}
	
	@PostMapping("/{courseId}/enroll/student/{studentId}")
	@PreAuthorize("hasAuthority('Student')")
	public void enrollStudentInCourse(@PathVariable Long courseId, @PathVariable Long studentId) {
		courseService.assignStudentToCourse(courseId, studentId);
	}
}
