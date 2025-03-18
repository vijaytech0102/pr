package com.airport.capstone.controller;


import com.airport.capstone.entity.User;
import com.airport.capstone.entity.enums.ApprovalStatus;
import com.airport.capstone.entity.enums.Role;
import com.airport.capstone.payload.RegistrationRequest;
import com.airport.capstone.payload.RegistrationResponse;
import com.airport.capstone.payload.UserDto;
import com.airport.capstone.repository.UserRepository;
import com.airport.capstone.service.UserService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;


@Tag(name = "2. User Controller")
@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private  UserService userService;

    @Operation(summary = "Registration a new user", description = "This endpoint allows users to sign up with a specified role")
    @PostMapping("/signUp")
    public ResponseEntity<RegistrationResponse> signUp(@Validated @RequestBody RegistrationRequest registrationRequest, @RequestParam("role") Set<Role> role) {
        RegistrationResponse response = userService.signUp(registrationRequest, role);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }
    
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping("/approve/{userId}")
    @Operation(summary = "Approve a user", description = "This endpoint allows an admin to approve a user by their ID")
    public ResponseEntity<?> approveUser(@PathVariable Long userId) {
        User user=userService.getUserById(userId);
        user.setApprovalStatus(ApprovalStatus.APPROVED);
        userService.updateUser(user);
        return ResponseEntity.ok("User approved successfully");
    }
    
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping("/reject/{userId}")
    @Operation(summary = "Reject a user", description = "This endpoint allows an admin to reject a user by their ID with a reason")
    public ResponseEntity<?> rejectUser(@PathVariable Long userId, @RequestParam String rejectedReason) throws Exception{
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//        authorities.forEach(authority -> System.out.println(authority.getAuthority()));
    
    	
    	userService.rejectUser(userId, rejectedReason);
        
        return ResponseEntity.ok("User rejected successfully");
    }
    
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping("/managers")
    @Operation(summary = "Get managers by status")
    public ResponseEntity<?> getAllPendingManagers(@RequestParam("status") ApprovalStatus status){
    	if(ApprovalStatus.REJECTED==status) {
    		return ResponseEntity.ok(userService.getRejectedManagers());
    	}
    	List<UserDto> user= userService.getManagersByStatus(status);
        return ResponseEntity.ok(user);
    }
    
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping("/all-managers")
    @Operation(summary = "Get all managers")
    public ResponseEntity<?> getAllManagers(){
    	List<UserDto> user= userService.getAllManagers();
        return ResponseEntity.ok(user);
    }
    
    @Operation(summary = "Show the current user details")
    @GetMapping("/profile")
    public ResponseEntity<UserDto> profileDetails() {
        UserDto user = userService.getProfileDetails();
        return ResponseEntity.ok(user);
    }

}
