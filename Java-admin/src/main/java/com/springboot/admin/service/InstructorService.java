package com.springboot.admin.service;

import java.util.List;

import org.springframework.data.domain.Page;

import com.springboot.admin.dto.InstructorDTO;
import com.springboot.admin.entity.Instructor;

public interface InstructorService {

	Instructor loadInstructorById(Long instructorId);
	
	Page<InstructorDTO> findInstructorsByName(String name, int page, int size);
	
	InstructorDTO loadInstructorByEmail(String email);
	
	InstructorDTO createInstructor(InstructorDTO instructorDTO);
	
	InstructorDTO updateInstructor(InstructorDTO instructorDTO);
	
	List<InstructorDTO> fetchInstructors();
	
	void removeInstructor(Long instructorId);
}
