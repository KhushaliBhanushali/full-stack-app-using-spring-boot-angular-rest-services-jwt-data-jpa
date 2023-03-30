package com.springboot.admin.mapper;

import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;

import com.springboot.admin.dto.StudentDTO;
import com.springboot.admin.entity.Student;

@Service
public class StudentMapper {

	public StudentDTO fromStudent(Student student) {
		StudentDTO studentDTO = new StudentDTO();
		BeanUtils.copyProperties(student, studentDTO);
		return studentDTO;
	}
	
	public Student fromStudentDTO(StudentDTO studentDTO) {
		Student student = new Student();
		BeanUtils.copyProperties(studentDTO, student);
		return student;
	}
}
