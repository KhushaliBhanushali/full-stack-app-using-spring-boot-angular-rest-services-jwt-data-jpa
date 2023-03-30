package com.springboot.admin.mapper;

import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;

import com.springboot.admin.dto.InstructorDTO;
import com.springboot.admin.entity.Instructor;

@Service
public class InstructorMapper {

	// will use for (Ex.fetching from the database to the list of instruction)
	public InstructorDTO fromInstructor(Instructor instructor) {
		InstructorDTO instructorDTO = new InstructorDTO();
		
		// write below line for all the fields to map instructor to instructorDTO
		//instructorDTO.setInstructorId(instructor.getInstructorId());
		
		// enable us to copy utilizing source object(instructor) to target object(instructorDTO)
		BeanUtils.copyProperties(instructor, instructorDTO);
		return instructorDTO;
	}
	
	// we will use (Ex.when we post from the front-end application)
	public Instructor fromInstructorDTO(InstructorDTO instructorDTO) {
		Instructor instructor = new Instructor();
		BeanUtils.copyProperties(instructorDTO, instructor);
		return instructor;				
	}
}
