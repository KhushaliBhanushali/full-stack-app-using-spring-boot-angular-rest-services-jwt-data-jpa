package com.springboot.admin.mapper;

import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;

import com.springboot.admin.dto.CourseDTO;
import com.springboot.admin.entity.Course;

@Service
public class CourseMapper {

	private InstructorMapper instructorMapper;
	
	public CourseMapper(InstructorMapper instructorMapper) {
		super();
		this.instructorMapper = instructorMapper;
	}

	public CourseDTO fromCourse(Course course) {
		CourseDTO courseDTO = new CourseDTO();
		BeanUtils.copyProperties(course, courseDTO);
		courseDTO.setInstructor(instructorMapper.fromInstructor(course.getInstructor()));
		return courseDTO;
	}
	
	public Course fromCourseDTO(CourseDTO courseDTO) {
		Course course = new Course();
		BeanUtils.copyProperties(courseDTO, course);
		return course;
	}
}
