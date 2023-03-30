package com.springboot.admin.dao;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.springboot.admin.entity.Instructor;

public interface InstructorDao extends JpaRepository<Instructor, Long>{

//	@Query(value = "select i from Instructor as i where i.firstName like %:name% or i.lastName like %:name%")
//	List<Instructor> findInstructorsByName(@Param("name") String name);

	@Query(value = "select i from Instructor as i where i.firstName like %:name% or i.lastName like %:name%")
	Page<Instructor> findInstructorsByName(@Param("name") String name, PageRequest pageRequest);
	
	@Query(value = "select i from Instructor as i where i.user.email=:email")
	Instructor findInstructorsByEmail(@Param("email") String email);
}
