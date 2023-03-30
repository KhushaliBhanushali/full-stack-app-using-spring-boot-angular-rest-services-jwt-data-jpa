package com.springboot.admin.service.impl;

import java.util.stream.Collectors;

import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.springboot.admin.dao.CourseDao;
import com.springboot.admin.dao.InstructorDao;
import com.springboot.admin.dao.StudentDao;
import com.springboot.admin.dto.CourseDTO;
import com.springboot.admin.entity.Course;
import com.springboot.admin.entity.Instructor;
import com.springboot.admin.entity.Student;
import com.springboot.admin.mapper.CourseMapper;
import com.springboot.admin.service.CourseService;

@Service
@Transactional
public class CourseServiceImpl implements CourseService{
	
	private CourseDao courseDao;
	private CourseMapper courseMapper;
	private InstructorDao instructorDao;
	private StudentDao studentDao;

	public CourseServiceImpl(CourseDao courseDao, CourseMapper courseMapper, InstructorDao instructorDao,
			StudentDao studentDao) {
		super();
		this.courseDao = courseDao;
		this.courseMapper = courseMapper;
		this.instructorDao = instructorDao;
		this.studentDao = studentDao;
	}

	@Override
	public Course loadCourseById(Long courseId) {
		return courseDao.findById(courseId).orElseThrow(() -> new EntityNotFoundException("Course with id " +courseId+ " not found"));
	}

	@Override
	public CourseDTO createCourse(CourseDTO courseDTO) {
		Course course = courseMapper.fromCourseDTO(courseDTO);
		Instructor instructor = instructorDao.findById(courseDTO.getInstructor().getInstructorId()).orElseThrow(() -> new EntityNotFoundException("Instructor with id " +courseDTO.getInstructor().getInstructorId()+ "not found"));
		course.setInstructor(instructor);
		Course savedCourse = courseDao.save(course);
		return courseMapper.fromCourse(savedCourse);
	}

	@Override
	public CourseDTO updateCourse(CourseDTO courseDTO) {
		Course loadedCourse = loadCourseById(courseDTO.getCourseId());
		Instructor instructor = instructorDao.findById(courseDTO.getInstructor().getInstructorId()).orElseThrow(() -> new EntityNotFoundException("Instructor with id " +courseDTO.getInstructor().getInstructorId()+ "not found"));
		Course course = courseMapper.fromCourseDTO(courseDTO);
		course.setInstructor(instructor);
		course.setStudents(loadedCourse.getStudents());
		Course updatedCourse = courseDao.save(course);
		return courseMapper.fromCourse(updatedCourse);
	}

	@Override
	public void removeCourse(Long courseId) {
		courseDao.deleteById(courseId);
	}

	@Override
	public Page<CourseDTO> findCoursesByCourseName(String keyword, int page, int size) {
		PageRequest pageRequest = PageRequest.of(page, size);
		Page<Course> coursesPage = courseDao.findCoursesByCourseNameContains(keyword, pageRequest);
		return new PageImpl<>(coursesPage.getContent().stream().map(course -> courseMapper.fromCourse(course)).collect(Collectors.toList()), pageRequest, coursesPage.getTotalElements());
	}

	@Override
	public void assignStudentToCourse(Long courseId, Long studentId) {
		Student student = studentDao.findById(studentId).orElseThrow(() -> new EntityNotFoundException("Student with id " +studentId+ " not found"));;
		Course course = loadCourseById(courseId);
		course.assignStudentToCourse(student);
	}

	@Override
	public Page<CourseDTO> fetchCoursesForStudent(Long studentId, int page, int size) {
		PageRequest pageRequest = PageRequest.of(page, size);
		Page<Course> studentCoursesPage = courseDao.getCoursesByStudentId(studentId, pageRequest);
		return new PageImpl<>(studentCoursesPage.getContent().stream().map(course -> courseMapper.fromCourse(course)).collect(Collectors.toList()), pageRequest, studentCoursesPage.getTotalElements());
	}

	@Override
	public Page<CourseDTO> fetchNonEnrolledInCoursesForStudent(Long studentId, int page, int size) {
		PageRequest pageRequest = PageRequest.of(page, size);
		Page<Course> nonEnrolledInCoursesPage = courseDao.getNonEnrolledInCoursesByStudentId(studentId, pageRequest);
		return new PageImpl<>(nonEnrolledInCoursesPage.getContent().stream().map(course -> courseMapper.fromCourse(course)).collect(Collectors.toList()), pageRequest, nonEnrolledInCoursesPage.getTotalElements());
	}

	@Override
	public Page<CourseDTO> fetchCoursesForInstructor(Long instructorId, int page, int size) {
		PageRequest pageRequest = PageRequest.of(page, size);
		Page<Course> instructoeCoursesPage = courseDao.getCoursesByInstructorId(instructorId, pageRequest);
		return new PageImpl<>(instructoeCoursesPage.getContent().stream().map(course -> courseMapper.fromCourse(course)).collect(Collectors.toList()), pageRequest, instructoeCoursesPage.getTotalElements());
	}

}
