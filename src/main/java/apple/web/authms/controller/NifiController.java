package apple.web.authms.controller;


import apple.web.authms.implementation.ByteArrayMultipartFile;
import apple.web.authms.model.OrganizationsWithDepartments;
import apple.web.authms.model.UploadFileRequest;
import java.util.*;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("api/v1/nifi")
public class NifiController {

    @Value("${upload.allowedFileTypes}")
    private String allowedFileTypes;

    private RestTemplate restTemplate = new RestTemplate();


    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(NifiController.class);


    @PostMapping(path = "/upload")
    public ResponseEntity<?> upload(
            @ModelAttribute UploadFileRequest uploadFileRequest, HttpServletRequest request)
            throws ErrorResponseException {

        logger.info(String.valueOf(request));

        List<MultipartFile> files = uploadFileRequest.getFiles();
        List<String> fileIds = uploadFileRequest.getFileIds();

        List<OrganizationsWithDepartments> contributingOrganizationsWithDepartments =
                uploadFileRequest.getContributors();

        // Basic validation (doesn't throw errors, just logs them)
        List<String> allowedFilesList = Arrays.asList(allowedFileTypes.split(",", -1));
        for (MultipartFile file : files) {
            if (!allowedFilesList.contains(file.getContentType())) {
                logger.info("Invalid file type: {}", file.getContentType());
            }
        }

        if (files.size() != fileIds.size()) {
            logger.info("Mismatch between files and fileIds count: {} files, {} fileIds", files.size(), fileIds.size());
        }

        if (contributingOrganizationsWithDepartments == null || contributingOrganizationsWithDepartments.isEmpty()) {
            logger.info("No contributors provided");
        } else {
            for (OrganizationsWithDepartments orgWithDept : contributingOrganizationsWithDepartments) {
                if (orgWithDept.getOrganization() == null || orgWithDept.getOrganization().isEmpty()) {
                    logger.info("Organization cannot be empty");
                }
                if (orgWithDept.getDepartment() == null || orgWithDept.getDepartment().isEmpty()) {
                    logger.info("Department cannot be empty");
                }
            }
        }

        // Returning a simple response to indicate the method was hit successfully
        return ResponseEntity.ok("Upload processed successfully.");
    }


    @PostMapping(path = "/intermediary")
    public ResponseEntity<?> handleFlowFileUpload(
            @RequestBody byte[] fileData,  // Accept the raw binary data
            @RequestHeader("fileId") String fileId,
            @RequestHeader("fileName") String fileName,
            @RequestHeader("organization") String organization,
            @RequestHeader("department") String department,
            @RequestHeader(value = "links", required = false) List<String> links) {

        logger.info("Received upload request from NiFi.");
        logger.info("fileName: {}", fileName);
        logger.info("Organization: {}", organization);
        logger.info("Department: {}", department);
        logger.info("File ID: {}", fileId);
        logger.info("Links: {}", links != null ? links : "No links provided");


        // Map of file extensions to MIME types
        Map<String, String> mimeTypeMap = new HashMap<>();
        mimeTypeMap.put("doc", "application/msword");
        mimeTypeMap.put("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
        mimeTypeMap.put("pdf", "application/pdf");

        // Extract the file extension
        String fileExtension = "";
        int i = fileName.lastIndexOf('.');
        if (i > 0) {
            fileExtension = fileName.substring(i + 1).toLowerCase();
        }

        // Determine MIME type based on file extension
        String mimeType = mimeTypeMap.get(fileExtension);

        if (mimeType == null) {
            // If the MIME type is not in the allowed list, throw an exception
            logger.error("Unsupported file type: {}", fileExtension);
            throw new IllegalArgumentException("Unsupported file type: " + fileExtension);
        }

        // Convert byte[] to MultipartFile using the detected MIME type
        MultipartFile multipartFile = new ByteArrayMultipartFile(fileData, fileName, mimeType);

        logger.info("Converted file: {}, MIME type: {}, Size: {} bytes", multipartFile.getOriginalFilename(), multipartFile.getContentType(), multipartFile.getSize());

        // Prepare the UploadFileRequest object
        UploadFileRequest uploadFileRequest = new UploadFileRequest();
        uploadFileRequest.setFiles(Collections.singletonList(multipartFile));
        uploadFileRequest.setFileIds(Collections.singletonList(fileId));

        if (links != null) {
            uploadFileRequest.setLinks(Optional.of(links));
        } else {
            uploadFileRequest.setLinks(Optional.empty());
        }

        OrganizationsWithDepartments contributors = new OrganizationsWithDepartments();
        contributors.setOrganization(organization);
        contributors.setDepartment(department);

        uploadFileRequest.setContributors(Collections.singletonList(contributors));

        // Now call the /upload endpoint with the UploadFileRequest object
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("files", multipartFile.getResource());
        body.add("fileIds", fileId);
        if (links != null) {
            body.add("links", links);
        }
        body.add("contributors[0].organization", organization);
        body.add("contributors[0].department", department);

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        logger.info("Forwarding request to /upload endpoint with the following details: {}", requestEntity);

        ResponseEntity<?> response = restTemplate.postForEntity("http://localhost:8081/api/v1/nifi/upload", requestEntity, String.class);

        logger.info("Received response from /upload endpoint: {}", response.getStatusCode());

        return ResponseEntity.ok(response.getBody());
    }
}

